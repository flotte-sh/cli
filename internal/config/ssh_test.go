package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keyDirFromHome derives the ssh key dir the same way WriteKnownHosts does.
func keyDirFromHome(home string) string {
	return filepath.Join(home, ".flotte", "ssh")
}

func TestWriteKnownHostsOverwritesWithCurrentHostOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	keyDir := keyDirFromHome(home)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	knownHosts := filepath.Join(keyDir, "known_hosts")
	existing := "alpha ssh-ed25519 AAAAalpha\nalpha ecdsa-sha2-nistp256 AAAAsha\nbeta ssh-rsa AAAAbeta\n"
	if err := os.WriteFile(knownHosts, []byte(existing), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := WriteKnownHosts("alpha", "22", []string{"ssh-ed25519 AAAANew"}); err != nil {
		t.Fatalf("WriteKnownHosts: %v", err)
	}

	got, err := os.ReadFile(knownHosts)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	content := string(got)

	// The current host's new hostkey must be present exactly once.
	want := "alpha ssh-ed25519 AAAANew\n"
	if content != want {
		t.Fatalf("known_hosts = %q, want %q", content, want)
	}
	// Other hosts must be removed entirely.
	if strings.Contains(content, "beta") {
		t.Fatalf("expected other host beta removed, got:\n%s", content)
	}
	if strings.Contains(content, "AAAAsha") {
		t.Fatalf("expected stale hostkey removed, got:\n%s", content)
	}
}

func TestWriteKnownHostsMultipleKeys(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	keyDir := keyDirFromHome(home)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := WriteKnownHosts("gamma", "22", []string{"ssh-ed25519 AAAAGamma", "ssh-rsa AAAAGamma2"}); err != nil {
		t.Fatalf("WriteKnownHosts: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(keyDir, "known_hosts"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want := "gamma ssh-ed25519 AAAAGamma\ngamma ssh-rsa AAAAGamma2\n"
	if string(got) != want {
		t.Fatalf("known_hosts = %q, want %q", got, want)
	}
}

func TestWriteKnownHostsNonDefaultPort(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	keyDir := keyDirFromHome(home)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := WriteKnownHosts("server", "2222", []string{"ssh-ed25519 AAAANew"}); err != nil {
		t.Fatalf("WriteKnownHosts: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(keyDir, "known_hosts"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Non-default port is written as [host]:port in known_hosts.
	want := "[server]:2222 ssh-ed25519 AAAANew\n"
	if string(got) != want {
		t.Fatalf("known_hosts = %q, want %q", got, want)
	}
}
