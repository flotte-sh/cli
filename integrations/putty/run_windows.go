//go:build windows

package putty

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/flotte-sh/cli/integrations/internal/agentserver"
	"github.com/flotte-sh/cli/integrations/internal/certagent"
	"github.com/flotte-sh/cli/integrations/internal/pageant"
	"github.com/flotte-sh/cli/integrations/internal/target"
	"github.com/flotte-sh/cli/internal/sshhelper"
)

func Run(ctx context.Context, options Options) error {
	if options.Input == nil {
		options.Input = os.Stdin
	}
	if options.Output == nil {
		options.Output = os.Stdout
	}
	if options.Errors == nil {
		options.Errors = os.Stderr
	}
	host, port, err := target.Split(options.Address)
	if err != nil {
		return fmt.Errorf("invalid PuTTY target: %w", err)
	}
	executable, err := findPuTTY(options.Executable)
	if err != nil {
		return err
	}
	queryAddress := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	listener, pipePath, err := pageant.Listen()
	if err != nil {
		return fmt.Errorf("cannot exclusively create Pageant agent endpoint; stop Pageant or another Flotte desktop launcher and retry: %w", err)
	}
	hostKeyLine, err := sshhelper.QueryServerHostkey(queryAddress)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("get server host key: %w", err)
	}
	_, sessionPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("generate PuTTY session key: %w", err)
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	certificateAgent := certagent.New(sessionCtx, certagent.Config{
		ServerURL:                options.ServerURL,
		Token:                    options.Token,
		User:                     options.User,
		Errors:                   options.Errors,
		CloseAfterFirstSignature: true,
	}, hostKeyLine, sessionPrivateKey)
	defer certificateAgent.Close()
	approvedHostKeys, err := certificateAgent.HostKeys()
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("authorize PuTTY connection: %w", err)
	}
	arguments, err := launchArguments(options.User, options.Address, approvedHostKeys)
	if err != nil {
		_ = listener.Close()
		return err
	}
	agentDone := make(chan error, 1)
	go func() {
		agentDone <- agentserver.ServeOneSignature(sessionCtx, listener, certificateAgent)
	}()
	process := exec.Command(executable, arguments...) // #nosec G204 -- The local CLI user selects the executable; arguments are passed without a shell.
	process.Stdin = options.Input
	process.Stdout = options.Output
	process.Stderr = options.Errors
	fmt.Fprintf(options.Output, "Using one-use Pageant agent %s. It closes after delivering one signature; the PuTTY terminal remains running.\n", pipePath)
	if err := process.Start(); err != nil {
		cancel()
		_ = listener.Close()
		<-agentDone
		return fmt.Errorf("start PuTTY: %w", err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- process.Wait() }()
	select {
	case agentErr := <-agentDone:
		if errors.Is(agentErr, agentserver.ErrSignatureDelivered) {
			return nil
		}
		_ = process.Process.Kill()
		processErr := <-processDone
		if agentErr == nil {
			agentErr = errors.New("agent stopped before delivering an authentication signature")
		}
		return errors.Join(agentErr, processErr)
	case processErr := <-processDone:
		cancel()
		_ = listener.Close()
		agentErr := <-agentDone
		if errors.Is(agentErr, agentserver.ErrSignatureDelivered) {
			return nil
		}
		if processErr == nil {
			return errors.New("PuTTY exited before delivering an authentication signature")
		}
		return fmt.Errorf("PuTTY session failed before authentication: %w", processErr)
	case <-ctx.Done():
		cancel()
		_ = listener.Close()
		_ = process.Process.Kill()
		processErr := <-processDone
		<-agentDone
		return errors.Join(ctx.Err(), processErr)
	}
}
