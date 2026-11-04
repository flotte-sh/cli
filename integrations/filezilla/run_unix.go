//go:build !windows

package filezilla

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func listenAgentEndpoint() (agentEndpoint, error) {
	directory, err := os.MkdirTemp("", "flotte-filezilla-")
	if err != nil {
		return agentEndpoint{}, fmt.Errorf("create private FileZilla agent directory: %w", err)
	}
	socket := filepath.Join(directory, "agent.sock")
	if len(socket) >= 104 {
		_ = os.RemoveAll(directory)
		return agentEndpoint{}, fmt.Errorf("FileZilla agent socket path is too long: %s", socket)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		_ = os.RemoveAll(directory)
		return agentEndpoint{}, fmt.Errorf("listen on FileZilla agent socket: %w", err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = listener.Close()
		_ = os.RemoveAll(directory)
		return agentEndpoint{}, fmt.Errorf("restrict FileZilla agent socket permissions: %w", err)
	}
	return agentEndpoint{
		listener: listener,
		close: func() {
			_ = listener.Close()
			_ = os.RemoveAll(directory)
		},
		configureProcess: func(command *exec.Cmd) {
			command.Env = setEnvironment(os.Environ(), "SSH_AUTH_SOCK", socket)
		},
	}, nil
}

func setEnvironment(environment []string, name, value string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, name) {
			result = append(result, entry)
		}
	}
	return append(result, name+"="+value)
}
