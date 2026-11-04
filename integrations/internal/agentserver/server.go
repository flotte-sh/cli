package agentserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var ErrSignatureDelivered = errors.New("agent signature response delivered")

type signatureDeliveryObserver interface {
	SignatureResponseDelivered()
	SignatureResponseFailed()
}

type signatureState struct {
	mu        sync.Mutex
	reserved  bool
	delivered bool
}

type oneSignatureAgent struct {
	agent.ExtendedAgent
	state  *signatureState
	writer *responseWriter
}

func (a *oneSignatureAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *oneSignatureAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.state.mu.Lock()
	if a.state.reserved || a.state.delivered {
		a.state.mu.Unlock()
		return nil, errors.New("single-use agent signature already in progress or delivered")
	}
	a.state.reserved = true
	a.state.mu.Unlock()
	signature, err := a.ExtendedAgent.SignWithFlags(key, data, flags)
	if err != nil {
		a.state.mu.Lock()
		a.state.reserved = false
		a.state.mu.Unlock()
		return nil, err
	}
	a.writer.signaturePending = true
	return signature, nil
}

func Serve(ctx context.Context, listener net.Listener, backend agent.ExtendedAgent) error {
	return serve(ctx, listener, backend, false)
}

func ServeOneSignature(ctx context.Context, listener net.Listener, backend agent.ExtendedAgent) error {
	return serve(ctx, listener, backend, true)
}

func serve(ctx context.Context, listener net.Listener, backend agent.ExtendedAgent, oneSignature bool) error {
	var observer signatureDeliveryObserver
	if oneSignature {
		var ok bool
		observer, ok = backend.(signatureDeliveryObserver)
		if !ok {
			return fmt.Errorf("one-signature agent does not observe signature delivery")
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var connectionsMu sync.Mutex
	connections := make(map[net.Conn]struct{})
	var handlers sync.WaitGroup
	accepted := make(chan struct{})
	failures := make(chan error, 1)
	delivered := make(chan struct{})
	var deliveredOnce sync.Once
	state := &signatureState{}
	go func() {
		defer close(accepted)
		for {
			connection, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil {
					select {
					case failures <- fmt.Errorf("agent listener failed: %w", err):
					default:
					}
				}
				return
			}
			connectionsMu.Lock()
			connections[connection] = struct{}{}
			connectionsMu.Unlock()
			handlers.Go(func() {
				defer connection.Close()
				defer func() {
					connectionsMu.Lock()
					delete(connections, connection)
					connectionsMu.Unlock()
				}()
				if !oneSignature {
					_ = agent.ServeAgent(backend, connection)
					return
				}
				writer := &responseWriter{
					Conn:      connection,
					observer:  observer,
					state:     state,
					delivered: func() { deliveredOnce.Do(func() { close(delivered) }) },
				}
				protocol := &oneSignatureAgent{ExtendedAgent: backend, state: state, writer: writer}
				_ = agent.ServeAgent(protocol, writer)
			})
		}
	}()

	var serveErr error
	select {
	case <-ctx.Done():
		select {
		case <-delivered:
			serveErr = ErrSignatureDelivered
		default:
			serveErr = ctx.Err()
		}
	case <-delivered:
		serveErr = ErrSignatureDelivered
	case serveErr = <-failures:
	}
	cancel()
	_ = listener.Close()
	<-accepted
	connectionsMu.Lock()
	for connection := range connections {
		_ = connection.Close()
	}
	connectionsMu.Unlock()
	handlers.Wait()
	if closer, ok := backend.(interface{ Close() }); ok {
		closer.Close()
	}
	return serveErr
}

type responseWriter struct {
	net.Conn
	observer         signatureDeliveryObserver
	state            *signatureState
	delivered        func()
	signaturePending bool
	length           [4]byte
	lengthN          int
	remaining        uint64
	opcode           byte
}

func (w *responseWriter) Write(data []byte) (int, error) {
	original := data
	written := 0
	for len(data) > 0 {
		n, err := w.Conn.Write(data)
		written += n
		data = data[n:]
		if err != nil {
			w.fail(err)
			return written, err
		}
		if n == 0 {
			err = io.ErrShortWrite
			w.fail(err)
			return written, err
		}
	}
	w.consume(original)
	return written, nil
}

func (w *responseWriter) fail(_ error) {
	if !w.signaturePending {
		return
	}
	w.signaturePending = false
	w.state.mu.Lock()
	w.state.reserved = false
	w.state.mu.Unlock()
	w.observer.SignatureResponseFailed()
}

func (w *responseWriter) consume(data []byte) {
	for len(data) > 0 {
		if w.remaining == 0 {
			count := copy(w.length[w.lengthN:], data)
			w.lengthN += count
			data = data[count:]
			if w.lengthN == len(w.length) {
				w.remaining = uint64(binary.BigEndian.Uint32(w.length[:]))
				w.lengthN = 0
				w.opcode = 0
			}
			continue
		}
		count := uint64(len(data))
		if count > w.remaining {
			count = w.remaining
		}
		if w.remaining == uint64(binary.BigEndian.Uint32(w.length[:])) {
			w.opcode = data[0]
		}
		w.remaining -= count
		data = data[count:]
		if w.remaining == 0 && w.opcode == 14 && w.signaturePending {
			w.signaturePending = false
			w.state.mu.Lock()
			w.state.reserved = false
			w.state.delivered = true
			w.state.mu.Unlock()
			w.observer.SignatureResponseDelivered()
			w.delivered()
		}
	}
}

var _ io.ReadWriter = (*responseWriter)(nil)
