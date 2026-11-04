package openssh

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type bindingAgent struct {
	agent.ExtendedAgent
	err   error
	calls int
}

func (a *bindingAgent) Extension(string, []byte) ([]byte, error) {
	a.calls++
	return nil, a.err
}

func TestProxySigningAndBinding(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	remote := agent.NewKeyring()
	if err := remote.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	upstream := &bindingAgent{ExtendedAgent: remote.(agent.ExtendedAgent)}
	proxy := &proxyAgent{CertificateAgent: CertificateAgent{Agent: agent.NewKeyring()}, upstream: upstream}
	keys, err := proxy.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	sig, err := proxy.SignWithFlags(key, []byte("test"), agent.SignatureFlagRsaSha512)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA512 {
		t.Fatal(sig.Format)
	}
	if err := key.Verify([]byte("test"), sig); err != nil {
		t.Fatal(err)
	}
	if err := proxy.RemoveAll(); err == nil {
		t.Fatal("mutation allowed")
	}
	if _, err := proxy.Extension("unknown", nil); err != agent.ErrExtensionUnsupported {
		t.Fatal(err)
	}
	binding := ssh.Marshal(struct {
		HostKey, SessionID, Signature []byte
		Forwarded                     bool
	}{Forwarded: true})
	if _, err := proxy.Extension("session-bind@openssh.com", binding); err != nil {
		t.Fatal(err)
	}
	if upstream.calls != 1 || !proxy.forwarded {
		t.Fatal("binding not forwarded")
	}
	upstream.err = errors.New("binding rejected")
	if _, err := proxy.Extension("session-bind@openssh.com", binding); err == nil {
		t.Fatal("binding accepted")
	}
	if _, err := proxy.Sign(key, []byte("test")); err == nil {
		t.Fatal("signed after failed binding")
	}
}

func TestProxyClosesAfterFirstLocalSignature(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	local := agent.NewKeyring()
	if err := local.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	closeCalls := 0
	proxy := &proxyAgent{
		CertificateAgent: CertificateAgent{Agent: local},
		onLocalSign:      func() { closeCalls++ },
	}
	for range 2 {
		if _, err := proxy.Sign(key, []byte("test")); err != nil {
			t.Fatal(err)
		}
	}
	if closeCalls != 1 {
		t.Fatalf("close callback called %d times, want 1", closeCalls)
	}
}
