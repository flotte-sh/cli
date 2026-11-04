package openssh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

func agentEndpointPrefix() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return `\\.\pipe\flotte-` + user.User.Sid.String(), nil
}

func agentEndpointPath(prefix, connectionHash string) string {
	return prefix + "-" + connectionHash
}

func agentEndpointAvailable(prefix, connectionHash string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := winio.DialPipeContext(ctx, agentEndpointPath(prefix, connectionHash))
	if err != nil {
		return false
	}
	defer connection.Close()
	_, err = agent.NewClient(connection).List()
	return err == nil
}

func listenAgent(prefix, connectionHash string) (listener net.Listener, closeListener func(), err error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, nil, err
	}
	listener, err = winio.ListenPipe(agentEndpointPath(prefix, connectionHash), &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;" + user.User.Sid.String() + ")",
	})
	if err != nil {
		return nil, nil, err
	}
	return listener, func() { _ = listener.Close() }, nil
}

func serveWindowsCertificateAgent(ctx context.Context, output io.Writer, endpointPrefix, connectionHash string, credential Credential, initial agent.Agent, lifetime time.Duration) (windowsAgentHandled bool, err error) {
	provision, closeProvision, err := listenAgent(endpointPrefix, connectionHash+"-provision")
	if err != nil {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		connection, dialErr := winio.DialPipeContext(ctx, agentEndpointPath(endpointPrefix, connectionHash+"-provision"))
		if dialErr != nil {
			return true, fmt.Errorf("agent provisioning unavailable: %w", dialErr)
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		if err := json.NewEncoder(connection).Encode(credential); err != nil {
			return true, err
		}
		var response bool
		if err := json.NewDecoder(connection).Decode(&response); err != nil || !response {
			return true, fmt.Errorf("agent provisioning failed")
		}
		_, err = fmt.Fprintln(output, "ready")
		return true, err
	}
	defer closeProvision()
	listener, closeAgent, err := listenAgent(endpointPrefix, connectionHash)
	if err != nil {
		return true, err
	}
	defer closeAgent()
	var mutex sync.Mutex
	current := initial
	upstreamAgentSocket := credential.UpstreamAgentSocket
	timer := time.AfterFunc(lifetime, closeProvision)
	defer timer.Stop()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			mutex.Lock()
			snapshot := current
			remote := upstreamAgentSocket
			mutex.Unlock()
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(lifetime))
				serveProxy(connection, snapshot, remote, func() {
					time.AfterFunc(agentShutdownGrace, func() {
						closeProvision()
						closeAgent()
					})
				})
			}()
		}
	}()
	if _, err := fmt.Fprintln(output, "ready"); err != nil {
		return true, err
	}
	for {
		connection, err := provision.Accept()
		if err != nil {
			return true, nil
		}
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		var updated Credential
		decodeErr := json.NewDecoder(io.LimitReader(connection, 65536)).Decode(&updated)
		if decodeErr == nil {
			nextLifetime, next, validationErr := agentFromCredential(updated)
			if validationErr == nil {
				timer.Reset(nextLifetime)
				mutex.Lock()
				current = next
				upstreamAgentSocket = updated.UpstreamAgentSocket
				mutex.Unlock()
				_ = json.NewEncoder(connection).Encode(true)
			}
		}
		_ = connection.Close()
	}
}
