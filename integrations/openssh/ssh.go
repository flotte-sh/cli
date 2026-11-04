package openssh

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/flotte-sh/flotte-cli/internal/config"
	clierrors "github.com/flotte-sh/flotte-cli/internal/errors"
	"github.com/flotte-sh/flotte-cli/internal/sshhelper"
)

type sshMode uint8

const (
	sshModeNative sshMode = iota
	sshModeLegacy
)

func parseSSHArguments(sshArgs []string) (sshMode, []string) {
	mode := sshModeNative
	var forwardedArgs []string

	for index := 0; index < len(sshArgs); index++ {
		argument := sshArgs[index]
		if isSSHDestination(argument) || argument == "--" {
			forwardedArgs = append(forwardedArgs, sshArgs[index:]...)
			break
		}
		if isLegacySSHOption(sshArgs, index) {
			mode = sshModeLegacy
			if argument == "-o" {
				index++
			}
			continue
		}

		forwardedArgs = append(forwardedArgs, argument)
		forwardedArgs, index = appendSSHOptionValue(sshArgs, index, forwardedArgs)
	}

	return mode, forwardedArgs
}

func runNative(ctx context.Context, output, diagnostics io.Writer, sshArgs []string) error {
	if len(sshArgs) == 0 {
		return fmt.Errorf("OpenSSH destination is required; run 'flotte ssh --help' for usage")
	}
	options, err := nativeSSHOptions()
	if err != nil {
		return err
	}
	arguments := makeNativeSSHArguments(options, sshArgs)

	process := exec.CommandContext(ctx, "ssh", arguments...) // #nosec G204 -- Intentional OpenSSH argument passthrough from the local CLI user; no shell is involved.
	process.Stdin = os.Stdin
	process.Stdout = output
	process.Stderr = diagnostics
	return process.Run()
}

func makeNativeSSHArguments(options nativeSSHConfig, sshArgs []string) []string {
	arguments := []string{
		"-o", "KnownHostsCommand=" + options.knownHostsCommand,
		"-o", "IdentityAgent=" + options.identityAgentOption,
	}
	return append(arguments, sshArgs...)
}

func runLegacy(ctx context.Context, sshArgs []string, session Session) error {
	const operation = "ssh"

	if len(sshArgs) == 0 {
		return clierrors.New(operation, nil, "usage: flotte ssh --legacy [-p port] [user@]hostname [command...]")
	}

	token, err := session.Authenticate(ctx, operation, true)
	if err != nil {
		return err
	}

	loginUser, host, port, err := parseSSHCommand(sshArgs)
	if err != nil {
		return clierrors.Wrap(operation, err, "invalid SSH command format")
	}

	hostKeyLine, err := sshhelper.QueryServerHostkey(host + ":" + port)
	if err != nil {
		return clierrors.Wrapf(operation, err, "failed to get server hostkey for %s:%s", host, port)
	}

	publicKey, err := session.RequireSSHKey(operation)
	if err != nil {
		return err
	}

	result, err := session.RequestCertificate(ctx, token, publicKey, hostKeyLine, loginUser)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Certificate requested for:\nServer: %s\nPort: %s\nUser: %s\n\n", host, port, loginUser)
		return clierrors.Wrap(operation, err, clierrors.GetUserMessage(err))
	}

	certFile, err := os.CreateTemp("", "flotte-ssh-cert-*.pub")
	if err != nil {
		return clierrors.Wrap(operation, err, "failed to create temporary certificate file")
	}
	certFileName := certFile.Name()
	defer os.Remove(certFileName)

	if _, err := certFile.WriteString(result.Certificate); err != nil {
		_ = certFile.Close()
		return clierrors.Wrap(operation, err, "failed to write certificate")
	}

	if err := certFile.Close(); err != nil {
		return clierrors.Wrap(operation, err, "failed to close certificate file")
	}

	privateKeyPath, err := config.GetActiveSSHPrivateKeyPath()
	if err != nil {
		return clierrors.Wrap(operation, err, "failed to get SSH private key path")
	}

	if err := config.WriteKnownHosts(host, port, result.Hostkeys); err != nil {
		return clierrors.Wrap(operation, err, "failed to write known_hosts file")
	}

	keyDir, err := config.GetSSHKeyDir()
	if err != nil {
		return clierrors.Wrap(operation, err, "failed to get SSH key directory")
	}

	sshArgs = append([]string{
		"-i", privateKeyPath,
		"-o", "KnownHostsCommand=none",
		"-o", "IdentityAgent=none",
		"-o", fmt.Sprintf("UserKnownHostsFile=\"%s\"", keyDir+"/known_hosts"),
		"-o", fmt.Sprintf("CertificateFile=\"%s\"", certFile.Name()),
	}, sshArgs...)

	if result.Warning != "" {
		fmt.Printf("\x1b[33m%s\x1b[0m\n\n", result.Warning)
	}

	sshCmd := exec.CommandContext(ctx, "ssh", sshArgs...) //#nosec G204,G702
	sshCmd.Stdin = os.Stdin
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	sshCmd.Env = append(os.Environ(), "FLOTTE_INVOKED_SSH=1")

	if err := sshCmd.Run(); err != nil {
		return clierrors.Wrap(operation, err, "SSH connection failed")
	}

	return nil
}

func isSSHDestination(argument string) bool {
	return argument == "-" || !strings.HasPrefix(argument, "-")
}

func isLegacySSHOption(sshArgs []string, index int) bool {
	argument := sshArgs[index]
	if argument == "--legacy" || argument == "-olegacy" {
		return true
	}
	return argument == "-o" && index+1 < len(sshArgs) && sshArgs[index+1] == "legacy"
}

func appendSSHOptionValue(sshArgs []string, index int, forwardedArgs []string) ([]string, int) {
	argument := sshArgs[index]
	if len(argument) < 2 || argument[0] != '-' {
		return forwardedArgs, index
	}
	for optionIndex := 1; optionIndex < len(argument); optionIndex++ {
		if !sshOptionTakesSeparateValue(argument[optionIndex]) {
			continue
		}
		if optionIndex == len(argument)-1 && index+1 < len(sshArgs) {
			forwardedArgs = append(forwardedArgs, sshArgs[index+1])
			return forwardedArgs, index + 1
		}
		return forwardedArgs, index
	}
	return forwardedArgs, index
}

func sshOptionTakesSeparateValue(option byte) bool {
	switch option {
	case 'B', 'b', 'c', 'D', 'E', 'e', 'F', 'I', 'i', 'J', 'L', 'l', 'm', 'O', 'o', 'P', 'p', 'Q', 'R', 'S', 'W', 'w':
		return true
	default:
		return false
	}
}

func Run(ctx context.Context, output, diagnostics io.Writer, sshArgs []string, session Session) error {
	mode, forwardedArgs := parseSSHArguments(sshArgs)
	if mode == sshModeLegacy {
		return runLegacy(ctx, forwardedArgs, session)
	}
	return runNative(ctx, output, diagnostics, forwardedArgs)
}
