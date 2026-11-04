package openssh

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type proxyAgent struct {
	CertificateAgent
	upstream    agent.ExtendedAgent
	onLocalSign func()
	localSigned sync.Once
	blocked     bool
	forwarded   bool
}

const sessionBindingExtension = "session-bind@openssh.com"

func serveProxy(connection net.Conn, localAgent agent.Agent, upstreamAgentSocket string, onLocalSignature func()) {
	proxy := &proxyAgent{CertificateAgent: CertificateAgent{Agent: localAgent}, onLocalSign: onLocalSignature}
	if upstreamAgentSocket != "" && safeUpstreamAgentSocket(upstreamAgentSocket) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		remote, err := dialUpstreamAgentSocket(ctx, upstreamAgentSocket)
		cancel()
		if err == nil {
			defer remote.Close()
			proxy.upstream = agent.NewClient(remote)
		}
	}
	_ = agent.ServeAgent(proxy, connection)
}

func (a *proxyAgent) List() ([]*agent.Key, error) {
	keys, err := a.CertificateAgent.List()
	if err != nil {
		return nil, err
	}
	if a.forwarded {
		keys = nil
	}
	if a.upstream == nil || a.blocked {
		return keys, nil
	}
	remote, err := a.upstream.List()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	for _, key := range keys {
		seen[string(key.Blob)] = true
	}
	for _, key := range remote {
		if !seen[string(key.Blob)] {
			keys = append(keys, key)
			seen[string(key.Blob)] = true
		}
	}
	return keys, nil
}

func (a *proxyAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *proxyAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	keys, err := a.CertificateAgent.List()
	if err != nil {
		return nil, err
	}
	for _, local := range keys {
		if bytes.Equal(local.Blob, key.Marshal()) {
			if a.forwarded {
				return nil, fmt.Errorf("flotte certificate signing is disabled on forwarded agent connections")
			}
			if extended, ok := a.Agent.(agent.ExtendedAgent); ok {
				signature, err := extended.SignWithFlags(key, data, flags)
				if err == nil && a.onLocalSign != nil {
					a.localSigned.Do(a.onLocalSign)
				}
				return signature, err
			}
			if flags != 0 {
				return nil, fmt.Errorf("signature flags unsupported")
			}
			signature, err := a.CertificateAgent.Sign(key, data)
			if err == nil && a.onLocalSign != nil {
				a.localSigned.Do(a.onLocalSign)
			}
			return signature, err
		}
	}
	if a.upstream == nil || a.blocked {
		return nil, fmt.Errorf("upstream agent unavailable")
	}
	return a.upstream.SignWithFlags(key, data, flags)
}

func (a *proxyAgent) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("use the agent signing protocol")
}

func (a *proxyAgent) Extension(name string, contents []byte) ([]byte, error) {
	if name != sessionBindingExtension {
		return nil, agent.ErrExtensionUnsupported
	}
	var binding struct {
		HostKey   []byte
		SessionID []byte
		Signature []byte
		Forwarded bool
	}
	if err := ssh.Unmarshal(contents, &binding); err != nil {
		a.blocked = true
		a.forwarded = true
		return nil, err
	}
	// Never expose the unconstrained CLI key through a forwarded connection.
	a.forwarded = a.forwarded || binding.Forwarded
	if a.upstream == nil || a.blocked {
		return nil, agent.ErrExtensionUnsupported
	}
	response, err := a.upstream.Extension(name, contents)
	if err != nil {
		a.blocked = true
	}
	return response, err
}
