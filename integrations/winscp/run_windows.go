package winscp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/flotte-sh/cli/integrations/internal/agentserver"
	"github.com/flotte-sh/cli/integrations/internal/certagent"
	"github.com/flotte-sh/cli/integrations/internal/pageant"
	"github.com/flotte-sh/cli/internal/sshhelper"
	"golang.org/x/crypto/ssh"
)

func Run(ctx context.Context, options Options) error {
	sessionURL, err := winSCPSessionURL(options.User, options.Address)
	if err != nil {
		return err
	}
	executable, err := findWinSCP(options.Executable)
	if err != nil {
		return err
	}
	options.Executable = executable
	if options.Input == nil {
		options.Input = os.Stdin
	}
	if options.Output == nil {
		options.Output = os.Stdout
	}
	if options.Errors == nil {
		options.Errors = os.Stderr
	}
	var outputMutex sync.Mutex
	options.Output = synchronizedWriter{Writer: options.Output, mutex: &outputMutex}
	options.Errors = synchronizedWriter{Writer: options.Errors, mutex: &outputMutex}
	listener, pipePath, err := pageant.Listen()
	if err != nil {
		return fmt.Errorf("cannot exclusively create Pageant agent endpoint; stop Pageant or another Flotte desktop launcher and retry: %w", err)
	}
	defer listener.Close()
	hostKeyLine, err := sshhelper.QueryServerHostkey(options.Address)
	if err != nil {
		return fmt.Errorf("get server host key: %w", err)
	}
	hostPublicKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(hostKeyLine))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("invalid presented host key")
	}
	arguments, err := launchArguments(sessionURL, hostPublicKey)
	if err != nil {
		return err
	}
	_, sessionPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate WinSCP session key: %w", err)
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	certificateAgent := certagent.New(sessionCtx, certagent.Config{
		ServerURL: options.ServerURL,
		Token:     options.Token,
		User:      options.User,
		Errors:    options.Errors,
	}, hostKeyLine, sessionPrivateKey)
	defer certificateAgent.Close()

	agentDone := make(chan error, 1)
	go func() {
		serveErr := agentserver.Serve(sessionCtx, listener, certificateAgent)
		if sessionCtx.Err() == nil && serveErr != nil {
			cancel()
		}
		agentDone <- serveErr
	}()

	process := winSCPProcess(sessionCtx, options.Executable, arguments)
	process.Stdin = options.Input
	process.Stdout = options.Output
	process.Stderr = options.Errors
	fmt.Fprintf(options.Output, "Using Pageant agent %s. Certificates are requested on demand; keep this command and WinSCP running.\n", pipePath)
	processErr := process.Run()
	if processErr != nil {
		processErr = fmt.Errorf("WinSCP session failed: %w", processErr)
	}
	cancel()
	agentErr := <-agentDone
	if errors.Is(agentErr, context.Canceled) {
		agentErr = nil
	}
	if ctx.Err() == nil && agentErr != nil {
		agentErr = fmt.Errorf("WinSCP agent failed: %w", agentErr)
	}
	return errors.Join(ctx.Err(), agentErr, processErr)
}

func findWinSCP(explicitPath string) (string, error) {
	if explicitPath != "" {
		path, err := exec.LookPath(explicitPath)
		if err != nil {
			return "", fmt.Errorf("find WinSCP: %w", err)
		}
		return filepath.Abs(path)
	}
	if path, err := exec.LookPath("WinSCP.exe"); err == nil {
		return filepath.Abs(path)
	}
	for _, variable := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
		base := os.Getenv(variable)
		if base == "" {
			continue
		}
		for _, directory := range []string{"WinSCP", filepath.Join("Programs", "WinSCP")} {
			candidate := filepath.Join(base, directory, "WinSCP.exe")
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() { // #nosec G703 -- Local installation paths come from the CLI user's environment, not remote input.
				return filepath.Abs(candidate)
			}
		}
	}
	return "", fmt.Errorf("WinSCP.exe not found; install WinSCP or specify --winscp <path-to-WinSCP.exe>")
}

func launchArguments(sessionURL string, hostPublicKey ssh.PublicKey) ([]string, error) {
	fingerprint, err := certagent.WinSCPHostKeyFingerprint(hostPublicKey)
	if err != nil {
		return nil, err
	}
	return []string{
		sessionURL,
		"/newinstance",
		"/ini=nul",
		"/hostkey=" + fingerprint,
		"/rawsettings", "TryAgent=on", "AgentFwd=off", "AuthGSSAPI=off", "AuthKI=off",
		"/rawconfig", `Interface\AuthAgent=0`,
	}, nil
}
