package agentserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type protocolTestListener struct {
	accepted chan net.Conn
	closed   chan struct{}
	addr     net.Addr
}

func newProtocolTestListener() *protocolTestListener {
	return &protocolTestListener{
		accepted: make(chan net.Conn),
		closed:   make(chan struct{}),
		addr:     &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	}
}

func (listener *protocolTestListener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.accepted:
		return connection, nil
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *protocolTestListener) Close() error {
	select {
	case <-listener.closed:
	default:
		close(listener.closed)
	}
	return nil
}

func (listener *protocolTestListener) Addr() net.Addr { return listener.addr }

func (listener *protocolTestListener) Dial() (net.Conn, error) {
	select {
	case <-listener.closed:
		return nil, net.ErrClosed
	default:
	}
	client, server := net.Pipe()
	select {
	case listener.accepted <- server:
		return client, nil
	case <-listener.closed:
		_ = client.Close()
		_ = server.Close()
		return nil, net.ErrClosed
	}
}

type protocolTestAgent struct {
	public    ssh.PublicKey
	signer    ssh.Signer
	failList  atomic.Bool
	failSign  atomic.Bool
	delivered atomic.Bool
}

func (a *protocolTestAgent) List() ([]*agent.Key, error) {
	if a.failList.Load() {
		return nil, errors.New("list failed")
	}
	return []*agent.Key{{Format: a.public.Type(), Blob: a.public.Marshal()}}, nil
}

func (a *protocolTestAgent) Sign(_ ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if a.failSign.Load() {
		return nil, errors.New("sign failed")
	}
	return a.signer.Sign(rand.Reader, data)
}

func (a *protocolTestAgent) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	return a.Sign(key, data)
}

func (a *protocolTestAgent) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("agent protocol required")
}
func (a *protocolTestAgent) SignatureResponseDelivered() { a.delivered.Store(true) }
func (a *protocolTestAgent) SignatureResponseFailed()    {}
func (a *protocolTestAgent) Add(agent.AddedKey) error    { return errors.New("read-only") }
func (a *protocolTestAgent) Remove(ssh.PublicKey) error  { return errors.New("read-only") }
func (a *protocolTestAgent) RemoveAll() error            { return errors.New("read-only") }
func (a *protocolTestAgent) Lock([]byte) error           { return errors.New("read-only") }
func (a *protocolTestAgent) Unlock([]byte) error         { return errors.New("read-only") }
func (a *protocolTestAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func TestOneSignatureAgentWaitsForDeliveredSignature(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	implementation := &protocolTestAgent{public: publicKey, signer: signer}
	implementation.failList.Store(true)
	implementation.failSign.Store(true)
	listener := newProtocolTestListener()
	serverDone := make(chan error, 1)
	go func() { serverDone <- ServeOneSignature(t.Context(), listener, implementation) }()
	connection, err := listener.Dial()
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(connection)
	if _, err := client.List(); err == nil {
		t.Fatal("failed identity query succeeded")
	}
	implementation.failList.Store(false)
	if _, err := client.List(); err != nil {
		t.Fatalf("identity query after failure failed: %v", err)
	}
	if _, err := client.Sign(publicKey, []byte("failed signature")); err == nil {
		t.Fatal("failed signature succeeded")
	}
	implementation.failSign.Store(false)
	data := []byte("valid signature")
	signature, err := client.Sign(publicKey, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := publicKey.Verify(data, signature); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; !errors.Is(err, ErrSignatureDelivered) {
		t.Fatalf("server result = %v, want delivery", err)
	}
	_ = connection.Close()
	if _, err := listener.Dial(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("later connection error = %v, want closed listener", err)
	}
}

type blockedProtocolAgent struct {
	*protocolTestAgent
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (a *blockedProtocolAgent) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	a.once.Do(func() { close(a.started) })
	<-a.release
	return a.protocolTestAgent.Sign(key, data)
}

func TestOneSignatureAgentRejectsConcurrentSignature(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	implementation := &blockedProtocolAgent{
		protocolTestAgent: &protocolTestAgent{public: publicKey, signer: signer},
		started:           make(chan struct{}),
		release:           release,
	}
	listener := newProtocolTestListener()
	serverDone := make(chan error, 1)
	go func() { serverDone <- ServeOneSignature(t.Context(), listener, implementation) }()
	firstConnection, err := listener.Dial()
	if err != nil {
		t.Fatal(err)
	}
	secondConnection, err := listener.Dial()
	if err != nil {
		t.Fatal(err)
	}
	first := agent.NewClient(firstConnection)
	second := agent.NewClient(secondConnection)
	firstResult := make(chan error, 1)
	go func() {
		signature, err := first.Sign(publicKey, []byte("first"))
		if err == nil {
			err = publicKey.Verify([]byte("first"), signature)
		}
		firstResult <- err
	}()
	<-implementation.started
	if _, err := second.Sign(publicKey, []byte("second")); err == nil {
		t.Fatal("concurrent signature succeeded while first response was pending")
	}
	close(release)
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; !errors.Is(err, ErrSignatureDelivered) {
		t.Fatalf("server result = %v, want delivery", err)
	}
	_ = firstConnection.Close()
	_ = secondConnection.Close()
}
