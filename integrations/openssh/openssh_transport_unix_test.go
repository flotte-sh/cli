//go:build !windows

package openssh

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentEndpointPrefixUsesShortTemporaryDirectory(t *testing.T) {
	t.Setenv("TMPDIR", shortSocketDirectory)
	prefix, err := agentEndpointPrefix()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(shortSocketDirectory, fmt.Sprintf("flotte-agent-%d", os.Getuid()))
	if prefix != want {
		t.Fatalf("prefix = %q, want %q", prefix, want)
	}
}

func TestAgentEndpointPrefixFallsBackWhenTemporaryDirectoryIsLong(t *testing.T) {
	longTempDir := filepath.Join(t.TempDir(), strings.Repeat("x", unixSocketPathLimit))
	t.Setenv("TMPDIR", longTempDir)
	prefix, err := agentEndpointPrefix()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(shortSocketDirectory, fmt.Sprintf("flotte-agent-%d", os.Getuid()))
	if prefix != want {
		t.Fatalf("prefix = %q, want %q", prefix, want)
	}
	if !unixAgentSocketPathFits(prefix) {
		t.Fatalf("fallback socket path does not fit: %q", agentEndpointPath(prefix, strings.Repeat("0", agentConnectionHashLength)))
	}
}

func TestUnixAgentSocketPathLengthBoundary(t *testing.T) {
	for _, test := range []struct {
		name         string
		prefixLength int
		want         bool
	}{
		{name: "maximum fitting prefix", prefixLength: unixSocketPathLimit - agentConnectionHashLength - 2, want: true},
		{name: "limit prefix", prefixLength: unixSocketPathLimit - agentConnectionHashLength - 1, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := unixAgentSocketPathFits(strings.Repeat("x", test.prefixLength)); got != test.want {
				t.Fatalf("fits = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPrivateAgentDirectoryChecksModeAndOwner(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !privateAgentDirectory(info, os.Getuid()) {
		t.Fatal("accepted directory was not recognized as private and owned")
	}
	if privateAgentDirectory(info, os.Getuid()+1) {
		t.Fatal("accepted directory with a different owner")
	}
}

func TestListenAgentRejectsNonPrivateDirectory(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "agent")
	if err := os.Mkdir(prefix, 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, err := listenAgent(prefix, strings.Repeat("a", agentConnectionHashLength))
	if err == nil || !strings.Contains(err.Error(), "mode 0700") {
		t.Fatalf("listenAgent error = %v, want private-directory error", err)
	}
}

func TestListenAgentCreatesAndCleansSocket(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "agent")
	connectionHash := strings.Repeat("a", agentConnectionHashLength)
	listener, closeListener, err := listenAgent(prefix, connectionHash)
	if err != nil {
		t.Fatal(err)
	}
	defer closeListener()

	socketPath := agentEndpointPath(prefix, connectionHash)
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o, want 600", info.Mode().Perm())
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	closeListener()
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket still exists after cleanup: %v", err)
	}
}
