package start

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/flotte-sh/cli/integrations/openssh"
	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/config"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

func executeUninstall(t *testing.T) string {
	t.Helper()
	var warnings bytes.Buffer
	cmd := NewUninstallCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&warnings)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	return warnings.String()
}

func requireNoLocalSession(t *testing.T, home string) {
	t.Helper()
	if session, err := auth.LoadSession(); err == nil {
		t.Fatalf("session remains: %+v", session)
	}
	if secret, err := keyring.Get("flotte-cli", "opaque-token"); err == nil {
		t.Fatalf("keyring entry remains: %q", secret)
	}
	if _, err := os.Stat(filepath.Join(home, ".flotte", ".token.json")); !os.IsNotExist(err) {
		t.Fatalf("token file remains: %v", err)
	}
}

func revocationServer(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var revoked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/auth/logout" && r.Header.Get("X-flotte-token") == "cached-token" {
			revoked.Add(1)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, &revoked
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
	server, revoked := revocationServer(t, http.StatusNoContent)
	if err := auth.SaveToken(server.URL, "cached-token"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		cmd := NewUninstallCmd()
		if cmd.GroupID != "start" {
			t.Fatal("uninstall must share setup's group")
		}
		if warnings := executeUninstall(t); warnings != "" {
			t.Fatalf("unexpected warning: %q", warnings)
		}
	}
	if revoked.Load() != 1 {
		t.Fatalf("revocation requests = %d, want 1", revoked.Load())
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
	requireNoLocalSession(t, home)
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
		wantWarning  bool
	}{
		{name: "keyring", status: http.StatusNoContent},
		{name: "file fallback", keyringError: errors.New("keyring unavailable"), status: http.StatusNoContent},
		{name: "revocation fails", status: http.StatusInternalServerError, wantWarning: true},
		{name: "session already ended", status: http.StatusUnauthorized},
		{name: "server redirects", status: http.StatusFound, wantWarning: true},
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
			server, revoked := revocationServer(t, test.status)
			cfg := config.ClientConfig{FlotteUrl: server.URL}
			if err := cfg.Save(); err != nil {
				t.Fatal(err)
			}
			if err := auth.SaveToken(server.URL, "cached-token"); err != nil {
				t.Fatal(err)
			}

			warnings := executeUninstall(t)

			if revoked.Load() != 1 {
				t.Fatalf("revocation requests = %d, want 1", revoked.Load())
			}
			if warned := strings.Contains(warnings, "not ended on the server"); warned != test.wantWarning {
				t.Fatalf("warning = %q, want one: %t", warnings, test.wantWarning)
			}
			requireNoLocalSession(t, home)
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
	if err := auth.SaveToken(unreachableURL, "cached-token"); err != nil {
		t.Fatal(err)
	}

	if warnings := executeUninstall(t); !strings.Contains(warnings, "not ended on the server") {
		t.Fatalf("warning = %q", warnings)
	}

	requireNoLocalSession(t, home)
}

func TestUninstallEndsTheSessionAtTheServerThatIssuedIt(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(t *testing.T, otherServerURL string)
	}{
		{name: "another server is configured", configure: func(t *testing.T, otherServerURL string) {
			cfg := config.ClientConfig{FlotteUrl: otherServerURL}
			if err := cfg.Save(); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "no server is configured", configure: func(*testing.T, string) {}},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyring.MockInit()
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			issuer, revoked := revocationServer(t, http.StatusNoContent)
			var otherServerRequests atomic.Int32
			otherServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				otherServerRequests.Add(1)
			}))
			defer otherServer.Close()
			test.configure(t, otherServer.URL)
			if err := auth.SaveToken(issuer.URL, "cached-token"); err != nil {
				t.Fatal(err)
			}

			if warnings := executeUninstall(t); warnings != "" {
				t.Fatalf("unexpected warning: %q", warnings)
			}

			if revoked.Load() != 1 || otherServerRequests.Load() != 0 {
				t.Fatalf("revocations at the issuing server = %d, requests to the other server = %d", revoked.Load(), otherServerRequests.Load())
			}
			requireNoLocalSession(t, home)
		})
	}
}

func TestUninstallRemovesSessionDataItCannotRevoke(t *testing.T) {
	for _, test := range []struct {
		name        string
		plant       func(t *testing.T, home string)
		wantWarning bool
	}{
		{name: "keyring entry that is not a session", plant: func(t *testing.T, _ string) {
			if err := keyring.Set("flotte-cli", "opaque-token", "cached-token"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "file session without a server", plant: func(t *testing.T, home string) {
			writeTokenFile(t, home, `{"token":"cached-token"}`)
		}},
		{name: "corrupt token file", plant: func(t *testing.T, home string) {
			writeTokenFile(t, home, `{not json`)
		}},
		{name: "unusable session in both stores", plant: func(t *testing.T, home string) {
			if err := keyring.Set("flotte-cli", "opaque-token", "cached-token"); err != nil {
				t.Fatal(err)
			}
			writeTokenFile(t, home, `{"token":"cached-token"}`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyring.MockInit()
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			server, revoked := revocationServer(t, http.StatusNoContent)
			cfg := config.ClientConfig{FlotteUrl: server.URL}
			if err := cfg.Save(); err != nil {
				t.Fatal(err)
			}
			test.plant(t, home)

			warnings := executeUninstall(t)

			if revoked.Load() != 0 {
				t.Fatal("a session without a recorded server was sent to the configured server")
			}
			if warned := strings.Contains(warnings, "not ended on the server"); warned != test.wantWarning {
				t.Fatalf("warning = %q, want one: %t", warnings, test.wantWarning)
			}
			requireNoLocalSession(t, home)
		})
	}
}

func writeTokenFile(t *testing.T, home, content string) {
	t.Helper()
	directory := filepath.Join(home, ".flotte")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".token.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
