//go:build !windows

package openssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

const (
	unixSocketPathLimit       = 104
	agentConnectionHashLength = 40
	shortSocketDirectory      = "/tmp"
)

func agentEndpointPrefix() (string, error) {
	return agentEndpointPrefixFor(os.TempDir(), os.Getuid())
}

func agentEndpointPrefixFor(tempDir string, userID int) (string, error) {
	directoryName := fmt.Sprintf("flotte-agent-%d", userID)
	prefix := filepath.Join(tempDir, directoryName)
	if unixAgentSocketPathFits(prefix) {
		return prefix, nil
	}
	prefix = filepath.Join(shortSocketDirectory, directoryName)
	if !unixAgentSocketPathFits(prefix) {
		return "", fmt.Errorf("flotte agent directory path is too long for Unix sockets: %s", prefix)
	}
	return prefix, nil
}

func unixAgentSocketPathFits(prefix string) bool {
	return len(prefix)+1+agentConnectionHashLength < unixSocketPathLimit
}

func privateAgentDirectory(info os.FileInfo, userID int) bool {
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(stat.Uid) == int64(userID)
}

func agentEndpointPath(prefix, connectionHash string) string {
	return filepath.Join(prefix, connectionHash)
}

func agentEndpointAvailable(prefix, connectionHash string) bool {
	connection, err := net.DialTimeout("unix", agentEndpointPath(prefix, connectionHash), time.Second)
	if err != nil {
		return false
	}
	defer connection.Close()
	_, err = agent.NewClient(connection).List()
	return err == nil
}

func serveWindowsCertificateAgent(context.Context, io.Writer, string, string, Credential, agent.Agent, time.Duration) (bool, error) {
	return false, nil
}

func listenAgent(prefix, connectionHash string) (listener net.Listener, closeListener func(), err error) {
	if err := os.MkdirAll(prefix, 0o700); err != nil {
		return nil, nil, err
	}
	info, err := os.Lstat(prefix)
	if err != nil {
		return nil, nil, err
	}
	if !privateAgentDirectory(info, os.Getuid()) {
		return nil, nil, fmt.Errorf("agent directory must be owned by the current user with mode 0700")
	}
	temporary, err := os.CreateTemp(prefix, "agent-")
	if err != nil {
		return nil, nil, err
	}
	temporaryPath := temporary.Name()
	_ = temporary.Close()
	defer os.Remove(temporaryPath)
	if err := os.Remove(temporaryPath); err != nil {
		return nil, nil, err
	}
	unixListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: temporaryPath, Net: "unix"})
	if err != nil {
		return nil, nil, err
	}
	unixListener.SetUnlinkOnClose(false)
	listener = unixListener
	owned, err := os.Lstat(temporaryPath)
	if err != nil {
		_ = listener.Close()
		return nil, nil, err
	}
	path := agentEndpointPath(prefix, connectionHash)
	closeListener = func() {
		_ = listener.Close()
		current, statErr := os.Lstat(path)
		if statErr == nil && os.SameFile(owned, current) {
			_ = os.Remove(path)
		}
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		closeListener()
		return nil, nil, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		closeListener()
		return nil, nil, err
	}
	return listener, closeListener, nil
}
