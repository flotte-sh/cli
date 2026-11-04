package openssh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Credential struct {
	Certificate         string
	UpstreamAgentSocket string `json:",omitempty"`
}

const (
	minimumAgentLifetime = 120 * time.Second
	agentShutdownGrace   = 5 * time.Second
	agentStartupTimeout  = 10 * time.Second
	maxCredentialBytes   = 64 * 1024
)

func StartAgent(executablePath, connectionHash string, credential Credential) error {
	credential.UpstreamAgentSocket = os.Getenv("SSH_AUTH_SOCK")
	endpointPrefix, err := agentEndpointPrefix()
	if err != nil {
		return err
	}
	if agentEndpointAvailable(endpointPrefix, connectionHash) {
		return nil
	}
	data, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	process := exec.Command(executablePath, "ssh-agent-serve", connectionHash) // #nosec G204 -- Relaunch this CLI executable directly, without a shell; hash is validated.
	process.Stdin = bytes.NewReader(data)
	ready, err := process.StdoutPipe()
	if err != nil {
		return err
	}
	if err := process.Start(); err != nil {
		return err
	}
	timer := time.AfterFunc(agentStartupTimeout, func() { _ = process.Process.Kill() })
	defer timer.Stop()
	line, readErr := bufio.NewReader(ready).ReadString('\n')
	_ = ready.Close()
	if readErr != nil || line != "ready\n" {
		_ = process.Wait()
		if agentEndpointAvailable(endpointPrefix, connectionHash) {
			return nil
		}
		return fmt.Errorf("certificate agent failed to start")
	}
	return process.Process.Release()
}

func ServeAgent(ctx context.Context, input io.Reader, output io.Writer, endpointPrefix, connectionHash string) error {
	if !connectionHashPattern.MatchString(connectionHash) {
		return fmt.Errorf("invalid connection hash")
	}
	var credential Credential
	if err := json.NewDecoder(io.LimitReader(input, maxCredentialBytes)).Decode(&credential); err != nil {
		return err
	}
	lifetime, keyring, err := agentFromCredential(credential)
	if err != nil {
		return err
	}
	if windowsHandled, err := serveWindowsCertificateAgent(ctx, output, endpointPrefix, connectionHash, credential, keyring, lifetime); windowsHandled {
		return err
	}
	listener, closeListener, err := listenAgent(endpointPrefix, connectionHash)
	if err != nil {
		return err
	}
	defer closeListener()
	var connections sync.WaitGroup
	var closeOnce sync.Once
	closeAgent := func() {
		closeOnce.Do(func() { _ = listener.Close() })
	}
	markUsed := func() { time.AfterFunc(agentShutdownGrace, closeAgent) }
	timer := time.AfterFunc(lifetime, func() { _ = listener.Close() })
	defer timer.Stop()
	if _, err := fmt.Fprintln(output, "ready"); err != nil {
		return err
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			connections.Wait()
			return nil
		}
		connections.Go(func() {
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(lifetime))
			serveProxy(connection, keyring, credential.UpstreamAgentSocket, markUsed)
		})
	}
}

func certificateLifetime(certificate *ssh.Certificate) time.Duration {
	if certificate.ValidBefore == ssh.CertTimeInfinity {
		return minimumAgentLifetime
	}
	validBefore := certificate.ValidBefore
	if validBefore > uint64(math.MaxInt64) {
		validBefore = uint64(math.MaxInt64)
	}
	remaining := time.Until(time.Unix(int64(validBefore), 0)).Round(time.Second)
	if remaining < minimumAgentLifetime {
		return minimumAgentLifetime
	}
	return remaining
}

func agentFromCredential(credential Credential) (time.Duration, agent.Agent, error) {
	if credential.Certificate == "" {
		return minimumAgentLifetime, agent.NewKeyring(), nil
	}
	private, err := LoadCLIPrivateKey()
	if err != nil {
		return 0, nil, err
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(credential.Certificate))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return 0, nil, fmt.Errorf("invalid agent certificate")
	}
	certificate, ok := key.(*ssh.Certificate)
	if !ok || certificate.CertType != ssh.UserCert {
		return 0, nil, fmt.Errorf("API did not return a user certificate")
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return 0, nil, err
	}
	if !bytes.Equal(public.Marshal(), certificate.Key.Marshal()) {
		return 0, nil, fmt.Errorf("certificate does not match CLI private key")
	}
	lifetime := certificateLifetime(certificate)
	keyring := agent.NewKeyring()
	lifetimeSecs := int64(lifetime / time.Second)
	if lifetimeSecs > math.MaxUint32 {
		lifetimeSecs = math.MaxUint32
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: private, Certificate: certificate, LifetimeSecs: uint32(lifetimeSecs)}); err != nil {
		return 0, nil, err
	}
	return lifetime, keyring, nil
}
