package filezilla

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/flotte-sh/flotte-cli/integrations/internal/agentserver"
	"github.com/flotte-sh/flotte-cli/integrations/internal/certagent"
	"github.com/flotte-sh/flotte-cli/internal/sshhelper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Options struct {
	Executable string
	ServerURL  string
	Token      string
	Site       Site
	Input      io.Reader
	Output     io.Writer
	Errors     io.Writer
}

type agentEndpoint struct {
	listener         net.Listener
	close            func()
	configureProcess func(*exec.Cmd)
}

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
	var outputMu sync.Mutex
	options.Output = synchronizedWriter{Writer: options.Output, mutex: &outputMu}
	options.Errors = synchronizedWriter{Writer: options.Errors, mutex: &outputMu}

	if err := validateSite(options.Site); err != nil {
		return err
	}
	fileZillaExecutable, err := findFileZilla(options.Executable)
	if err != nil {
		return err
	}
	if err := requireSupportedVersion(ctx, fileZillaExecutable); err != nil {
		return err
	}
	address := net.JoinHostPort(options.Site.Host, strconv.Itoa(options.Site.Port))
	hostKeyLine, err := sshhelper.QueryServerHostkey(address)
	if err != nil {
		return fmt.Errorf("get server host key: %w", err)
	}
	_, sessionPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate FileZilla session key: %w", err)
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	certificateAgent := certagent.New(sessionCtx, certagent.Config{
		ServerURL: options.ServerURL,
		Token:     options.Token,
		User:      options.Site.User,
		Errors:    options.Errors,
	}, hostKeyLine, sessionPrivateKey)
	defer certificateAgent.Close()
	approvedHostKeys, err := certificateAgent.HostKeys()
	if err != nil {
		return fmt.Errorf("verify server host key with Flotte: %w", err)
	}
	sessionProfile, err := createSessionConfig(options.Site, approvedHostKeys)
	if err != nil {
		return err
	}
	defer sessionProfile.cleanup()
	endpoint, err := listenAgentEndpoint()
	if err != nil {
		return err
	}
	defer endpoint.close()

	agentDone := make(chan error, 1)
	signatureObserver := &observedAgent{ExtendedAgent: certificateAgent}

	go func() {
		agentDone <- agentserver.Serve(sessionCtx, endpoint.listener, signatureObserver)
	}()

	command := exec.CommandContext(sessionCtx, fileZillaExecutable, launchArguments()...) //#nosec G204 -- The executable is locally discovered or explicitly provided by the CLI user; arguments are passed without a shell.
	command.Stdin = options.Input
	command.Stdout = options.Output
	command.Stderr = options.Errors
	endpoint.configureProcess(command)
	sessionProfile.configureProcess(command)
	fmt.Fprintln(options.Output, "Using a temporary FileZilla profile with Flotte-approved host keys; keep this command and FileZilla running.")
	processDone := make(chan error, 1)

	go func() { processDone <- command.Run() }()

	var processErr, agentErr error
	select {
	case processErr = <-processDone:
		cancel()
		agentErr = <-agentDone
	case agentErr = <-agentDone:
		if sessionCtx.Err() == nil && agentErr != nil {
			agentErr = fmt.Errorf("FileZilla agent failed: %w", agentErr)
			cancel()
		}
		processErr = <-processDone
	case <-ctx.Done():
		cancel()
		processErr = <-processDone
		agentErr = <-agentDone
	}
	if errors.Is(agentErr, context.Canceled) {
		agentErr = nil
	}
	if sessionCtx.Err() == nil && agentErr != nil {
		agentErr = fmt.Errorf("FileZilla agent failed: %w", agentErr)
	}
	if processErr == nil && ctx.Err() == nil && !signatureObserver.signed.Load() {
		processErr = fmt.Errorf("FileZilla exited without using the Flotte SSH agent")
	}
	return errors.Join(ctx.Err(), agentErr, processErr)
}

type observedAgent struct {
	agent.ExtendedAgent
	signed atomic.Bool
}

func (a *observedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	signature, err := a.ExtendedAgent.Sign(key, data)
	if err == nil {
		a.signed.Store(true)
	}
	return signature, err
}

func (a *observedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	signature, err := a.ExtendedAgent.SignWithFlags(key, data, flags)
	if err == nil {
		a.signed.Store(true)
	}
	return signature, err
}

func launchArguments() []string {
	return []string{"--site=" + fileZillaSitePath}
}

func findFileZilla(explicitPath string) (string, error) {
	if explicitPath != "" {
		path, err := exec.LookPath(explicitPath)
		if err != nil {
			return "", fmt.Errorf("find FileZilla: %w", err)
		}
		return filepath.Abs(path)
	}
	for _, name := range []string{"filezilla", "FileZilla", "filezilla.exe"} {
		if path, err := exec.LookPath(name); err == nil {
			return filepath.Abs(path)
		}
	}
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		for _, variable := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
			if base := os.Getenv(variable); base != "" {
				candidates = append(candidates, filepath.Join(base, "FileZilla FTP Client", "filezilla.exe"))
			}
		}
	case "darwin":
		candidates = append(candidates,
			"/Applications/FileZilla.app/Contents/MacOS/filezilla",
			"/Applications/FileZilla.app/Contents/MacOS/FileZilla",
		)
		if home, err := os.UserHomeDir(); err == nil {
			candidates = append(candidates,
				filepath.Join(home, "Applications", "FileZilla.app", "Contents", "MacOS", "filezilla"),
				filepath.Join(home, "Applications", "FileZilla.app", "Contents", "MacOS", "FileZilla"),
			)
		}
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() { // #nosec G703 -- candidate paths are fixed installation suffixes combined with standard OS directories.
			return filepath.Abs(candidate)
		}
	}
	return "", fmt.Errorf("FileZilla not found; install FileZilla 3.71.0 or newer or specify --filezilla <path>")
}

var versionPattern = regexp.MustCompile(`([0-9]+)\.([0-9]+)\.([0-9]+)`)

func requireSupportedVersion(ctx context.Context, executable string) error {
	command := exec.CommandContext(ctx, executable, "--version") //#nosec G204 -- The executable is locally discovered or explicitly provided by the CLI user.
	output, err := command.CombinedOutput()
	return validateVersionOutput(output, err)
}

func validateVersionOutput(output []byte, commandErr error) error {
	version := strings.TrimSpace(string(output))
	if supportsCertificateAgent(version) {
		return nil
	}
	if commandErr != nil {
		return fmt.Errorf("check FileZilla version: %w: %s", commandErr, version)
	}
	return fmt.Errorf("FileZilla 3.71.0 or newer is required for SSH agent certificate identities; got %q", version)
}

func supportsCertificateAgent(output string) bool {
	match := versionPattern.FindStringSubmatch(output)
	if len(match) != 4 {
		return false
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(match[2])
	if err != nil {
		return false
	}
	return major > 3 || major == 3 && minor >= 71
}

type synchronizedWriter struct {
	io.Writer
	mutex *sync.Mutex
}

func (w synchronizedWriter) Write(data []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.Writer.Write(data)
}
