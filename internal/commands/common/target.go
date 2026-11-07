package common

import (
	"os"
	"path/filepath"
	"strings"

	clierrors "github.com/flotte-sh/cli/internal/errors"
)

func ParseSSHTarget(target string) (user, serverAddress string, err error) {
	const operation = "parseSSHTarget"

	parts := strings.SplitN(target, "@", 2)
	if len(parts) != 2 {
		return "", "", clierrors.New(operation, nil, "invalid format: expected user@server[:port], got "+target)
	}

	user = parts[0]
	serverAddress = parts[1]

	if user == "" {
		return "", "", clierrors.New(operation, nil, "username is required in format user@server[:port]")
	}

	if serverAddress == "" {
		return "", "", clierrors.New(operation, nil, "server address is required in format user@server[:port]")
	}

	if !strings.Contains(serverAddress, ":") {
		serverAddress += ":22"
	}

	return user, serverAddress, nil
}

func ResolvePublicKey(arg string) (string, error) {
	expanded := arg
	if strings.HasPrefix(expanded, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", clierrors.New("resolvePublicKey", err, "failed to expand home directory")
		}
		expanded = home + expanded[1:]
	}

	cleaned := filepath.Clean(expanded)
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil || !strings.HasSuffix(resolved, ".pub") {
		return arg, nil
	}

	if info, err := os.Stat(resolved); err == nil && !info.IsDir() && info.Size() < 4096 && info.Mode().IsRegular() {
		data, err := os.ReadFile(resolved)
		if err != nil {
			return "", clierrors.New("resolvePublicKey", err, "failed to read public key file")
		}
		return strings.TrimSpace(string(data)), nil
	}
	return arg, nil
}
