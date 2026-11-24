package start

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/flotte-sh/cli/integrations/openssh"
	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/config"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

func executeUninstall(t *testing.T) {
	t.Helper()
	cmd := NewUninstallCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestUninstallIntegrations(t *testing.T) {
	keyring.MockInit()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := &Root{Command: &cobra.Command{Use: "flotte"}}
	shells := []string{"bash", "zsh", "fish", "powershell"}
	for _, shell := range shells {
		if _, err := installCompletion(root, shell); err != nil {
			t.Fatal(err)
		}
	}
	sshPath := filepath.Join(home, ".ssh", "config")
	if err := os.MkdirAll(filepath.Dir(sshPath), 0o700); err != nil {
		t.Fatal(err)
	}
	otherConfig := "Host example\n  HostName example.org\n"
	if err := os.WriteFile(sshPath, []byte(otherConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openssh.InstallConfig(); err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveToken("cached-token"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		cmd := NewUninstallCmd()
		if cmd.GroupID != "start" {
			t.Fatal("uninstall must share setup's group")
		}
		executeUninstall(t)
	}
	for _, shell := range shells {
		path, err := completionPath(shell)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s completion remains: %v", shell, err)
		}
	}
	content, err := os.ReadFile(sshPath)
	if err != nil || string(content) != otherConfig {
		t.Fatalf("SSH config not preserved: %q, %v", content, err)
	}
	if token, err := auth.LoadToken(); err == nil {
		t.Fatalf("session remains: %q", token)
	}
}

func TestUninstallWithoutIntegrations(t *testing.T) {
	keyring.MockInit()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	executeUninstall(t)
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatalf("uninstall created files: %v, %v", entries, err)
	}
}

func TestUninstallRevokesAndRemovesSession(t *testing.T) {
	for _, test := range []struct {
		name         string
		keyringError error
		status       int
	}{
		{name: "keyring", status: http.StatusNoContent},
		{name: "file fallback", keyringError: errors.New("keyring unavailable"), status: http.StatusNoContent},
		{name: "revocation fails", status: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.keyringError != nil {
				keyring.MockInitWithError(test.keyringError)
			} else {
				keyring.MockInit()
			}
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			var revoked atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/auth/logout" && r.Header.Get("X-flotte-token") == "cached-token" {
					revoked.Add(1)
				}
				w.WriteHeader(test.status)
			}))
			defer server.Close()
			cfg := config.ClientConfig{FlotteUrl: server.URL}
			if err := cfg.Save(); err != nil {
				t.Fatal(err)
			}
			if err := auth.SaveToken("cached-token"); err != nil {
				t.Fatal(err)
			}

			executeUninstall(t)

			if revoked.Load() != 1 {
				t.Fatalf("revocation requests = %d, want 1", revoked.Load())
			}
			if token, err := auth.LoadToken(); err == nil {
				t.Fatalf("session remains: %q", token)
			}
			if _, err := os.Stat(filepath.Join(home, ".flotte", ".token.json")); !os.IsNotExist(err) {
				t.Fatalf("token file remains: %v", err)
			}
			if _, err := config.LoadOrCreate(); err != nil {
				t.Fatalf("account configuration removed: %v", err)
			}
		})
	}
}

func TestUninstallRemovesSessionWhenServerUnreachable(t *testing.T) {
	keyring.MockInit()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	server := httptest.NewServer(http.NotFoundHandler())
	unreachableURL := server.URL
	server.Close()
	cfg := config.ClientConfig{FlotteUrl: unreachableURL}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveToken("cached-token"); err != nil {
		t.Fatal(err)
	}

	executeUninstall(t)

	if token, err := auth.LoadToken(); err == nil {
		t.Fatalf("session remains: %q", token)
	}
}
