package certagent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/flotte-sh/cli/internal/client"
	"github.com/flotte-sh/cli/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Config struct {
	ServerURL                string
	Token                    string
	User                     string
	Errors                   io.Writer
	CloseAfterFirstSignature bool
}

type Agent struct {
	ctx                      context.Context
	cancel                   context.CancelFunc
	config                   Config
	hostKeyLine              string
	signer                   ssh.Signer
	private                  ed25519.PrivateKey
	signerErr                error
	mu                       sync.Mutex
	current                  *ssh.Certificate
	hostkeys                 []ssh.PublicKey
	issued                   map[string]*ssh.Certificate
	fetching                 *certificateIssuance
	closed                   bool
	closeAfterFirstSignature bool
	delivered                bool
}

type certificateIssuance struct {
	done chan struct{}
	err  error
}

var _ agent.ExtendedAgent = (*Agent)(nil)

var errReadOnly = errors.New("flotte certificate agent is read-only")
var errClosed = errors.New("flotte certificate agent is closed")

func New(ctx context.Context, config Config, hostKeyLine string, sessionPrivateKey ed25519.PrivateKey) *Agent {
	ctx, cancel := context.WithCancel(ctx)
	a := &Agent{ctx: ctx, cancel: cancel, config: config, hostKeyLine: hostKeyLine, private: sessionPrivateKey, issued: make(map[string]*ssh.Certificate), closeAfterFirstSignature: config.CloseAfterFirstSignature}
	if len(sessionPrivateKey) != ed25519.PrivateKeySize {
		a.signerErr = errors.New("invalid session private key")
	} else {
		a.signer, a.signerErr = ssh.NewSignerFromKey(sessionPrivateKey)
	}
	return a
}
func (a *Agent) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closeLocked()
	cancel := a.cancel
	a.cancel = nil
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *Agent) closeLocked() {
	clear(a.private)
	a.private = nil
	a.signer = nil
	a.current = nil
	clear(a.issued)
	a.closed = true
}

func CertificateValid(certificate *ssh.Certificate) bool {
	unix := time.Now().Unix()
	if certificate == nil || unix < 0 {
		return false
	}
	current := uint64(unix)
	return current >= certificate.ValidAfter &&
		(current < certificate.ValidBefore || certificate.ValidBefore == ssh.CertTimeInfinity)
}

func ApprovedHostKeys(presentedHostKey string, approvedHostKeys []string) (ssh.PublicKey, []ssh.PublicKey, error) {
	presentedKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(presentedHostKey))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, fmt.Errorf("invalid presented host key")
	}
	matched := false
	keys := make([]ssh.PublicKey, 0, len(approvedHostKeys))
	for _, text := range approvedHostKeys {
		key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(text))
		if err != nil || len(bytes.TrimSpace(rest)) != 0 {
			return nil, nil, fmt.Errorf("server returned an invalid host key")
		}
		matched = matched || bytes.Equal(key.Marshal(), presentedKey.Marshal())
		keys = append(keys, key)
	}
	if !matched {
		return nil, nil, fmt.Errorf("presented host key is not approved by Flotte")
	}
	return presentedKey, keys, nil
}

func WinSCPHostFingerprints(presentedHostKey string, approvedHostKeys []string) (string, error) {
	_, keys, err := ApprovedHostKeys(presentedHostKey, approvedHostKeys)
	if err != nil {
		return "", err
	}
	fingerprints := make([]string, 0, len(keys))
	for _, key := range keys {
		fingerprint, err := WinSCPHostKeyFingerprint(key)
		if err != nil {
			return "", err
		}
		if !slices.Contains(fingerprints, fingerprint) {
			fingerprints = append(fingerprints, fingerprint)
		}
	}
	slices.Sort(fingerprints)
	return strings.Join(fingerprints, ";"), nil
}

func WinSCPHostKeyFingerprint(key ssh.PublicKey) (string, error) {
	cryptoKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return "", fmt.Errorf("unsupported WinSCP host key type: %s", key.Type())
	}
	var bits int
	switch public := cryptoKey.CryptoPublicKey().(type) {
	case ed25519.PublicKey:
		bits = 255
	case *rsa.PublicKey:
		bits = public.N.BitLen()
	case *ecdsa.PublicKey:
		bits = public.Params().BitSize
	default:
		return "", fmt.Errorf("unsupported WinSCP host key type: %s", key.Type())
	}
	return fmt.Sprintf("%s %d %s", key.Type(), bits, strings.TrimPrefix(ssh.FingerprintSHA256(key), "SHA256:")), nil
}

func ValidateCertificate(certificateText string, sessionPublicKey ssh.PublicKey, loginUser string) (*ssh.Certificate, error) {
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(certificateText))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("server returned an invalid SSH certificate")
	}
	certificate, ok := key.(*ssh.Certificate)
	if !ok || certificate.CertType != ssh.UserCert {
		return nil, fmt.Errorf("server did not return an SSH user certificate")
	}
	if !bytes.Equal(certificate.Key.Marshal(), sessionPublicKey.Marshal()) {
		return nil, fmt.Errorf("certificate does not match the session key")
	}
	if !slices.Contains(certificate.ValidPrincipals, loginUser) {
		return nil, fmt.Errorf("certificate does not permit login as %q", loginUser)
	}
	checker := ssh.CertChecker{
		SupportedCriticalOptions: []string{"source-address", "force-command", "verify-required"},
	}
	if err := checker.CheckCert(loginUser, certificate); err != nil {
		return nil, fmt.Errorf("invalid Flotte certificate: %w", err)
	}
	return certificate, nil
}

func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	if err := a.ctx.Err(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	if a.closed {
		a.mu.Unlock()
		return nil, errClosed
	}
	if a.signerErr != nil {
		a.mu.Unlock()
		return nil, a.signerErr
	}
	if CertificateValid(a.current) {
		keys := a.identities()
		a.mu.Unlock()
		return keys, nil
	}
	if flight := a.fetching; flight != nil {
		a.mu.Unlock()
		select {
		case <-a.ctx.Done():
			return nil, a.ctx.Err()
		case <-flight.done:
			if flight.err != nil {
				return nil, flight.err
			}
			return a.List()
		}
	}
	flight := &certificateIssuance{done: make(chan struct{})}
	a.fetching = flight
	publicKey := a.signer.PublicKey()
	a.mu.Unlock()

	certificate, hostkeys, err := a.requestCertificate(publicKey)
	a.mu.Lock()
	defer a.mu.Unlock()
	if cancellation := a.ctx.Err(); cancellation != nil {
		err = cancellation
	}
	if a.closed {
		err = errClosed
	}
	if err == nil {
		for blob, issued := range a.issued {
			if !CertificateValid(issued) {
				delete(a.issued, blob)
			}
		}
		a.current = certificate
		a.hostkeys = hostkeys
		a.issued[string(certificate.Marshal())] = certificate
	} else if a.ctx.Err() == nil && !a.closed && a.config.Errors != nil {
		fmt.Fprintf(a.config.Errors, "Flotte certificate issuance failed: %v\n", err)
	}
	flight.err = err
	a.fetching = nil
	close(flight.done)
	if err != nil {
		return nil, err
	}
	return a.identities(), nil
}

func (a *Agent) requestCertificate(publicKey ssh.PublicKey) (*ssh.Certificate, []ssh.PublicKey, error) {
	response, err := client.RequestCertificate(a.ctx, &config.ClientConfig{FlotteUrl: a.config.ServerURL}, a.config.Token,
		string(ssh.MarshalAuthorizedKey(publicKey)), a.hostKeyLine, a.config.User)
	if err != nil {
		return nil, nil, err
	}
	_, hostkeys, err := ApprovedHostKeys(a.hostKeyLine, response.Hostkeys)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := ValidateCertificate(response.Certificate, publicKey, a.config.User)
	if err != nil {
		return nil, nil, err
	}
	if response.Warning != "" && a.config.Errors != nil {
		fmt.Fprintln(a.config.Errors, response.Warning)
	}
	return certificate, hostkeys, nil
}

func (a *Agent) HostKeys() ([]ssh.PublicKey, error) {
	if _, err := a.List(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, errClosed
	}
	return slices.Clone(a.hostkeys), nil
}

func (a *Agent) identities() []*agent.Key {
	return []*agent.Key{{Format: a.current.Type(), Blob: a.current.Marshal(), Comment: "Flotte certificate"}}
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ctx.Err(); err != nil {
		return nil, err
	}
	if a.closed {
		return nil, errClosed
	}
	if flags != 0 {
		return nil, errors.New("unsupported Ed25519 signature flags")
	}
	if key == nil || !CertificateValid(a.issued[string(key.Marshal())]) {
		return nil, errors.New("certificate was not issued by this agent or is no longer valid")
	}
	return a.signer.Sign(nil, data)
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("use the agent signing protocol")
}

func (a *Agent) Add(agent.AddedKey) error   { return errReadOnly }
func (a *Agent) Remove(ssh.PublicKey) error { return errReadOnly }
func (a *Agent) RemoveAll() error           { return errReadOnly }
func (a *Agent) Lock([]byte) error          { return errReadOnly }
func (a *Agent) Unlock([]byte) error        { return errReadOnly }
func (a *Agent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func (a *Agent) SignatureResponseDelivered() {
	a.mu.Lock()
	delivered := a.closeAfterFirstSignature
	if delivered {
		a.delivered = true
	}
	a.mu.Unlock()
	if delivered {
		a.Close()
	}
}

func (a *Agent) SignatureResponseFailed() {}

func (a *Agent) SignatureDelivered() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.delivered
}
