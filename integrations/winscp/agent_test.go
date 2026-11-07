package winscp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flotte-sh/cli/integrations/internal/certagent"
	"github.com/flotte-sh/cli/internal/client"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type certificateAgentFixture struct {
	validFor atomic.Int64
	requests atomic.Int64
	private  ed25519.PrivateKey
	hostkey  string
	agent    *certagent.Agent
	options  Options
	logs     bytes.Buffer
}

func newCertificateAgentFixture(t *testing.T, ctx context.Context, gate <-chan struct{}, started chan<- struct{}, change func(*ssh.Certificate, *client.SshCertResponse)) *certificateAgentFixture {
	t.Helper()
	f := &certificateAgentFixture{
		private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{37}, ed25519.SeedSize)),
		hostkey: winSCPTestAuthorizedKey(winSCPTestSigner(t, 38).PublicKey()),
	}
	f.validFor.Store(60)
	ca := winSCPTestSigner(t, 39)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		f.requests.Add(1)
		var input client.SshCertRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			http.Error(writer, "invalid request", http.StatusBadRequest)
			return
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(input.PublicKeyString))
		if err != nil || input.ServerUser != "alice" || input.ServerHostkey != f.hostkey || request.Header.Get("X-flotte-token") != "test-session-token" {
			http.Error(writer, "invalid scope", http.StatusBadRequest)
			return
		}
		if started != nil {
			started <- struct{}{}
		}
		if gate != nil {
			select {
			case <-gate:
			case <-request.Context().Done():
				return
			}
		}
		issuedAt := time.Now().Unix()
		certificate := &ssh.Certificate{
			Key: key, CertType: ssh.UserCert, ValidPrincipals: []string{"alice"},
			ValidAfter: uint64(issuedAt - 1), ValidBefore: uint64(issuedAt + f.validFor.Load()),
		}
		response := &client.SshCertResponse{Hostkeys: []string{f.hostkey}}
		if change != nil {
			change(certificate, response)
		}
		if err := certificate.SignCert(rand.Reader, ca); err != nil {
			http.Error(writer, "cannot sign certificate", http.StatusInternalServerError)
			return
		}
		response.Certificate = winSCPTestAuthorizedKey(certificate)
		_ = json.NewEncoder(writer).Encode(response)
	}))
	t.Cleanup(server.Close)
	f.options = Options{ServerURL: server.URL, Token: "test-session-token", User: "alice", Errors: &f.logs}
	f.agent = certagent.New(ctx, certagent.Config{
		ServerURL: f.options.ServerURL,
		Token:     f.options.Token,
		User:      f.options.User,
		Errors:    &f.logs,
	}, f.hostkey, f.private)
	return f
}

func certificateAgentProtocol(t *testing.T, implementation agent.Agent) agent.ExtendedAgent {
	t.Helper()
	server, connection := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		_ = agent.ServeAgent(implementation, server)
	}()
	t.Cleanup(func() {
		_ = connection.Close()
		<-done
	})
	return agent.NewClient(connection)
}

func certificateAgentIdentity(t *testing.T, protocol agent.Agent) *ssh.Certificate {
	t.Helper()
	keys, err := protocol.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("identities = %d, want one certificate", len(keys))
	}
	key, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	certificate, ok := key.(*ssh.Certificate)
	if !ok || keys[0].Format != certificate.Type() {
		t.Fatal("agent offered a raw or malformed identity")
	}
	return certificate
}

func TestCertificateAgentDemandAndExpiry(t *testing.T) {
	f := newCertificateAgentFixture(t, t.Context(), nil, nil, nil)
	f.validFor.Store(2)
	protocol := certificateAgentProtocol(t, f.agent)
	public, err := ssh.NewPublicKey(f.private.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.Sign(public, []byte("unissued payload")); err == nil {
		t.Fatal("signed a raw identity before issuance")
	}
	if got := f.requests.Load(); got != 0 {
		t.Fatalf("idle agent issued %d requests", got)
	}
	first := certificateAgentIdentity(t, protocol)
	second := certificateAgentIdentity(t, protocol)
	if f.requests.Load() != 1 || !bytes.Equal(first.Marshal(), second.Marshal()) {
		t.Fatal("repeated identity queries issued or rotated credentials")
	}
	data := []byte("SSH authentication payload")
	signature, err := protocol.Sign(first, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Key.Verify(data, signature); err != nil {
		t.Fatalf("certificate signature did not use the session key: %v", err)
	}
	if err := (&ssh.CertChecker{}).CheckCert("alice", first); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	unissued := winSCPTestCertificate(t, first.Key, ssh.UserCert, []string{"alice"}, now.Add(-time.Second), now.Add(120*time.Second))
	for _, rejected := range []ssh.PublicKey{first.Key, unissued} {
		if _, err := protocol.Sign(rejected, data); err == nil {
			t.Fatal("signed an identity that was never offered")
		}
	}
	if _, err := protocol.SignWithFlags(first, data, agent.SignatureFlagRsaSha512); err == nil {
		t.Fatal("accepted RSA signature flags for Ed25519")
	}
	deadline := time.Now().Add(4 * time.Second)
	for certagent.CertificateValid(first) {
		if time.Now().After(deadline) {
			t.Fatal("certificate did not expire")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := protocol.Sign(first, data); err == nil {
		t.Fatal("signed an expired certificate")
	}
	if f.requests.Load() != 1 {
		t.Fatalf("signing triggered certificate issuance: %d", f.requests.Load())
	}
	next := certificateAgentIdentity(t, protocol)
	if f.requests.Load() != 2 || bytes.Equal(first.Marshal(), next.Marshal()) || !bytes.Equal(first.Key.Marshal(), next.Key.Marshal()) {
		t.Fatal("expiry did not issue a new certificate for the same in-memory key")
	}
	if _, err := protocol.Sign(first, data); err == nil {
		t.Fatal("signed stale identity after issuing a replacement")
	}
	if signature, err := protocol.Sign(next, data); err != nil {
		t.Fatal(err)
	} else if err := next.Key.Verify(data, signature); err != nil {
		t.Fatal(err)
	}
	if f.logs.Len() != 0 {
		t.Fatalf("successful operations emitted errors: %s", f.logs.String())
	}
}

func TestCertificateAgentConcurrentListCoalesces(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 32)
	f := newCertificateAgentFixture(t, t.Context(), gate, started, nil)
	const clients = 16
	protocols := make([]agent.ExtendedAgent, clients)
	for i := range protocols {
		protocols[i] = certificateAgentProtocol(t, f.agent)
	}
	var group sync.WaitGroup
	results := make(chan []*agent.Key, clients)
	failures := make(chan error, clients)
	for _, protocol := range protocols {
		group.Go(func() {
			keys, err := protocol.List()
			results <- keys
			failures <- err
		})
	}
	<-started
	close(gate)
	group.Wait()
	var offered []byte
	for range clients {
		if err := <-failures; err != nil {
			t.Fatal(err)
		}
		keys := <-results
		if len(keys) != 1 {
			t.Fatalf("identities = %d", len(keys))
		}
		if offered == nil {
			offered = keys[0].Blob
		} else if !bytes.Equal(offered, keys[0].Blob) {
			t.Fatal("concurrent clients received different certificates")
		}
	}
	if got := f.requests.Load(); got != 1 {
		t.Fatalf("concurrent identity queries issued %d certificates", got)
	}
}

func TestCertificateAgentReadOnly(t *testing.T) {
	f := newCertificateAgentFixture(t, t.Context(), nil, nil, nil)
	protocol := certificateAgentProtocol(t, f.agent)
	key := winSCPTestSigner(t, 40).PublicKey()
	for name, operation := range map[string]func() error{
		"add":        func() error { return protocol.Add(agent.AddedKey{PrivateKey: f.private}) },
		"remove":     func() error { return protocol.Remove(key) },
		"remove all": protocol.RemoveAll,
		"lock":       func() error { return protocol.Lock([]byte("password")) },
		"unlock":     func() error { return protocol.Unlock([]byte("password")) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil {
				t.Fatal("accepted mutation")
			}
		})
	}
	if _, err := protocol.Extension("unknown@flotte.test", nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Fatalf("extension error = %v", err)
	}
	if _, err := f.agent.Signers(); err == nil {
		t.Fatal("provided stale signer snapshots")
	}
	if f.requests.Load() != 0 {
		t.Fatal("mutation or extension fetched a certificate")
	}
}

func TestCertificateAgentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	f := newCertificateAgentFixture(t, ctx, gate, started, nil)
	protocols := []agent.ExtendedAgent{certificateAgentProtocol(t, f.agent), certificateAgentProtocol(t, f.agent)}
	results := make(chan error, len(protocols))
	for _, protocol := range protocols {
		go func() {
			_, err := protocol.List()
			results <- err
		}()
	}
	<-started
	cancel()
	for range protocols {
		if err := <-results; err == nil {
			t.Fatal("cancelled issuance succeeded")
		}
	}
	if _, err := protocols[0].List(); err == nil {
		t.Fatal("issued after cancellation")
	}
	if f.requests.Load() != 1 || f.logs.Len() != 0 {
		t.Fatal("cancellation retried issuance or logged a spurious failure")
	}
}

func TestCertificateAgentCancellationRejectsSigning(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := newCertificateAgentFixture(t, ctx, nil, nil, nil)
	protocol := certificateAgentProtocol(t, f.agent)
	certificate := certificateAgentIdentity(t, protocol)
	cancel()
	if _, err := protocol.Sign(certificate, []byte("payload")); err == nil {
		t.Fatal("signed after cancellation")
	}
	if _, err := protocol.List(); err == nil {
		t.Fatal("returned a cached certificate after cancellation")
	}
	if f.requests.Load() != 1 {
		t.Fatal("cancellation triggered new issuance")
	}
}

func TestCertificateAgentRejectsInvalidIssuance(t *testing.T) {
	other := winSCPTestSigner(t, 41).PublicKey()
	for name, change := range map[string]func(*ssh.Certificate, *client.SshCertResponse){
		"unapproved host": func(_ *ssh.Certificate, response *client.SshCertResponse) {
			response.Hostkeys = []string{winSCPTestAuthorizedKey(other)}
		},
		"wrong key": func(certificate *ssh.Certificate, _ *client.SshCertResponse) { certificate.Key = other },
		"wrong principal": func(certificate *ssh.Certificate, _ *client.SshCertResponse) {
			certificate.ValidPrincipals = []string{"mallory"}
		},
		"expired": func(certificate *ssh.Certificate, _ *client.SshCertResponse) {
			certificate.ValidBefore = certificate.ValidAfter
		},
		"future":           func(certificate *ssh.Certificate, _ *client.SshCertResponse) { certificate.ValidAfter += 30 },
		"host certificate": func(certificate *ssh.Certificate, _ *client.SshCertResponse) { certificate.CertType = ssh.HostCert },
	} {
		t.Run(name, func(t *testing.T) {
			f := newCertificateAgentFixture(t, t.Context(), nil, nil, change)
			protocol := certificateAgentProtocol(t, f.agent)
			if keys, err := protocol.List(); err == nil || len(keys) != 0 {
				t.Fatalf("accepted invalid issuance: keys=%v err=%v", keys, err)
			}
			if f.requests.Load() != 1 || f.logs.Len() == 0 {
				t.Fatal("issuance failure was not reported")
			}
			if strings.Contains(f.logs.String(), f.options.Token) || strings.Contains(f.logs.String(), "PRIVATE KEY") || strings.Contains(f.logs.String(), f.hostkey) {
				t.Fatal("issuance log contains credentials")
			}
			public, err := ssh.NewPublicKey(f.private.Public())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := protocol.Sign(public, []byte("payload")); err == nil {
				t.Fatal("signed following rejected issuance")
			}
			if f.requests.Load() != 1 {
				t.Fatal("signing after rejection retried issuance")
			}
		})
	}
}
