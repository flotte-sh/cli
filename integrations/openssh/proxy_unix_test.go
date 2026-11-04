//go:build !windows

package openssh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectFlotteUpstreamAliases(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "flotte-agent-123")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "socket")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{path, alias, "relative", ""} {
		if safeUpstreamAgentSocket(path) {
			t.Fatalf("accepted loop/invalid path %q", path)
		}
	}
}
