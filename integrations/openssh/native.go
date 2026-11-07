package openssh

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	clierrors "github.com/flotte-sh/cli/internal/errors"
	"golang.org/x/crypto/ssh"
)

const (
	sshHostKeyOrder    = "ORDER"
	sshHostKeyHostname = "HOSTNAME"
	sshHostKeyAddress  = "ADDRESS"
)

var nativeSSHConfigPattern = regexp.MustCompile(`(?ms)^# BEGIN FLOTTE OPENSSH\r?\n.*?^# END FLOTTE OPENSSH\r?\n(?:\r?\n)?`)

// unmanagedHostAPIErrorMessage is the backend error body returned when the
// connected host is not managed by Flotte; ssh-hostkeys exits 0 without keys.
const unmanagedHostAPIErrorMessage = "server not found"

type nativePaths struct {
	executablePath      string
	agentEndpointPrefix string
}

func nativeSSHPaths() (nativePaths, error) {
	executablePath := argv[0]
	if !filepath.IsAbs(executablePath) {
		var err error
		executablePath, err = os.Executable()
		if err != nil {
			return nativePaths{}, err
		}
	}
	endpointPrefix, err := agentEndpointPrefix()
	if err != nil {
		return nativePaths{}, err
	}
	if strings.ContainsAny(executablePath+endpointPrefix, "\n\r%") {
		return nativePaths{}, fmt.Errorf("SSH integration paths cannot contain newlines or percent signs")
	}
	return nativePaths{executablePath: executablePath, agentEndpointPrefix: endpointPrefix}, nil
}

type nativeSSHConfig struct {
	knownHostsCommand   string
	identityAgentOption string
}

func nativeSSHOptions() (nativeSSHConfig, error) {
	paths, err := nativeSSHPaths()
	if err != nil {
		return nativeSSHConfig{}, err
	}
	executablePath := paths.executablePath
	agentPath := agentEndpointPath(paths.agentEndpointPrefix, "%C")
	if goos == "windows" {
		executablePath = strings.ReplaceAll(executablePath, `\`, `/`)
		agentPath = strings.ReplaceAll(agentPath, `\`, `/`)
	}
	knownHostsValue := "\"" + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(executablePath) + "\" ssh-hostkeys %I %H %r %t %K %C"
	return nativeSSHConfig{
		knownHostsCommand:   knownHostsValue,
		identityAgentOption: "\"" + agentPath + "\"",
	}, nil
}

var startCertificateAgent = func(connectionHash string, credential Credential) error {
	paths, err := nativeSSHPaths()
	if err != nil {
		return err
	}
	return StartAgent(paths.executablePath, connectionHash, credential)
}

func Hostkeys(ctx context.Context, output, diagnostics io.Writer, knownHostsArgs []string, session Session) error {
	if len(knownHostsArgs) != 6 {
		return fmt.Errorf("accepts 6 arg(s), received %d", len(knownHostsArgs))
	}
	lookupReason := knownHostsArgs[0]
	hostname := knownHostsArgs[1]
	remoteUser := knownHostsArgs[2]
	presentedKeyBase64 := knownHostsArgs[4]
	connectionHash := knownHostsArgs[5]
	if lookupReason == sshHostKeyOrder {
		return nil
	}
	if lookupReason != sshHostKeyHostname && lookupReason != sshHostKeyAddress {
		return fmt.Errorf("unsupported host-key lookup reason")
	}
	if !connectionHashPattern.MatchString(connectionHash) || strings.ContainsAny(hostname, " \t\r\n,*?!|") {
		return fmt.Errorf("invalid OpenSSH target")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(presentedKeyBase64)
	if err != nil {
		return fmt.Errorf("invalid presented host key encoding: %w", err)
	}
	presentedHostKey, err := ssh.ParsePublicKey(keyBytes)
	if err != nil {
		return fmt.Errorf("invalid presented host key: %w", err)
	}
	token, err := session.Authenticate(ctx, "ssh-hostkeys", false)
	if err != nil {
		if isFlotteUnavailableError(err) {
			return nil
		}
		return err
	}
	privateKey, err := LoadCLIPrivateKey()
	if err != nil {
		return err
	}
	sessionPublicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return err
	}
	result, err := session.RequestCertificate(ctx, token, string(ssh.MarshalAuthorizedKey(sessionPublicKey)), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(presentedHostKey))), remoteUser)
	if isUnmanagedHostAPIError(err) {
		if os.Getenv("SSH_AUTH_SOCK") == "" {
			return nil
		}
		_ = startCertificateAgent(connectionHash, Credential{})
		return nil
	}
	if err != nil {
		if isFlotteUnavailableError(err) {
			return nil
		}
		return err
	}
	var hostkeys strings.Builder
	approved := false
	for _, text := range result.Hostkeys {
		key, _, _, rest, parseErr := ssh.ParseAuthorizedKey([]byte(text))
		if parseErr != nil || len(bytes.TrimSpace(rest)) != 0 {
			return fmt.Errorf("API returned an invalid host key")
		}
		approved = approved || bytes.Equal(key.Marshal(), presentedHostKey.Marshal())
		fmt.Fprintf(&hostkeys, "%s %s", hostname, ssh.MarshalAuthorizedKey(key))
	}
	if !approved {
		return fmt.Errorf("presented host key is not approved by Flotte")
	}
	if err := startCertificateAgent(connectionHash, Credential{Certificate: result.Certificate}); err != nil {
		return err
	}
	if result.Warning != "" {
		fmt.Fprintln(diagnostics, result.Warning)
	}

	_, err = io.WriteString(output, hostkeys.String())
	return err
}

func isUnmanagedHostAPIError(err error) bool {
	var apiErr *clierrors.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound && apiErr.Message == unmanagedHostAPIErrorMessage
}

func isFlotteUnavailableError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return true
	}
	var urlError *url.Error
	return errors.As(err, &urlError) && urlError.Err != nil
}
