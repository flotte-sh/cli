package account

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

	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/config"
	"github.com/zalando/go-keyring"
)

const logoutNotEndedWarning = "not ended on the server"

func executeLogout(t *testing.T) (string, string) {
	t.Helper()
	var stdout, warnings bytes.Buffer
	cmd := NewLogoutCmd(&Root{})
	cmd.SetOut(&stdout)
	cmd.SetErr(&warnings)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("logout: %v", err)
	}
	return stdout.String(), warnings.String()
}

func logoutServer(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var ended atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/auth/logout" && r.Header.Get("X-flotte-token") == "cached-token" {
			ended.Add(1)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, &ended
}

func useEmptyHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func requireLoggedOutLocally(t *testing.T, home string) {
	t.Helper()
	if session, err := auth.LoadSession(); err == nil {
		t.Fatalf("session remains on this computer: %+v", session)
	}
	if _, err := os.Stat(filepath.Join(home, ".flotte", ".token.json")); !os.IsNotExist(err) {
		t.Fatalf("token file remains: %v", err)
	}
}

func TestLogoutEndsTheSessionOnTheServer(t *testing.T) {
	for _, test := range []struct {
		name         string
		keyringError error
		status       int
		wantWarning  bool
	}{
		{name: "keyring", status: http.StatusNoContent},
		{name: "file fallback", keyringError: errors.New("keyring unavailable"), status: http.StatusNoContent},
		{name: "session already ended", status: http.StatusUnauthorized},
		{name: "server fails", status: http.StatusInternalServerError, wantWarning: true},
		{name: "server redirects", status: http.StatusFound, wantWarning: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.keyringError != nil {
				keyring.MockInitWithError(test.keyringError)
			} else {
				keyring.MockInit()
			}
			home := useEmptyHome(t)
			server, ended := logoutServer(t, test.status)
			cfg := config.ClientConfig{FlotteUrl: server.URL}
			if err := cfg.Save(); err != nil {
				t.Fatal(err)
			}
			if err := auth.SaveToken(server.URL, "cached-token"); err != nil {
				t.Fatal(err)
			}

			stdout, warnings := executeLogout(t)

			if ended.Load() != 1 {
				t.Fatalf("logout requests to the server = %d, want 1", ended.Load())
			}
			if warned := strings.Contains(warnings, logoutNotEndedWarning); warned != test.wantWarning {
				t.Fatalf("warning = %q, want one: %t", warnings, test.wantWarning)
			}
			if !strings.Contains(stdout, "Successfully logged out.") {
				t.Fatalf("stdout = %q", stdout)
			}
			requireLoggedOutLocally(t, home)
		})
	}
}

func TestLogoutEndsTheSessionAtTheServerThatIssuedIt(t *testing.T) {
	keyring.MockInit()
	home := useEmptyHome(t)
	issuer, endedAtIssuer := logoutServer(t, http.StatusNoContent)
	configured, endedAtConfigured := logoutServer(t, http.StatusNoContent)
	cfg := config.ClientConfig{FlotteUrl: configured.URL}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveToken(issuer.URL, "cached-token"); err != nil {
		t.Fatal(err)
	}

	if _, warnings := executeLogout(t); warnings != "" {
		t.Fatalf("unexpected warning: %q", warnings)
	}

	if endedAtIssuer.Load() != 1 || endedAtConfigured.Load() != 0 {
		t.Fatalf("logout requests: issuing server %d, configured server %d, want 1 and 0", endedAtIssuer.Load(), endedAtConfigured.Load())
	}
	requireLoggedOutLocally(t, home)
}

func TestLogoutRemovesTheSessionWhenTheServerIsUnreachable(t *testing.T) {
	keyring.MockInit()
	home := useEmptyHome(t)
	server := httptest.NewServer(http.NotFoundHandler())
	unreachableURL := server.URL
	server.Close()
	if err := auth.SaveToken(unreachableURL, "cached-token"); err != nil {
		t.Fatal(err)
	}

	if _, warnings := executeLogout(t); !strings.Contains(warnings, logoutNotEndedWarning) {
		t.Fatalf("warning = %q", warnings)
	}

	requireLoggedOutLocally(t, home)
}

func TestLogoutNeverSendsASessionSavedWithoutItsServer(t *testing.T) {
	keyring.MockInit()
	home := useEmptyHome(t)
	var requests atomic.Int32
	configured := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer configured.Close()
	cfg := config.ClientConfig{FlotteUrl: configured.URL}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set("flotte-cli", "opaque-token", "token-without-a-server"); err != nil {
		t.Fatal(err)
	}

	if _, warnings := executeLogout(t); warnings != "" {
		t.Fatalf("warning = %q", warnings)
	}

	if requests.Load() != 0 {
		t.Fatalf("requests to the configured server = %d, want 0", requests.Load())
	}
	requireLoggedOutLocally(t, home)
}

func TestLogoutWithoutASessionDoesNotWarn(t *testing.T) {
	keyring.MockInit()
	useEmptyHome(t)

	stdout, warnings := executeLogout(t)

	if warnings != "" || !strings.Contains(stdout, "Successfully logged out.") {
		t.Fatalf("stdout = %q, warnings = %q", stdout, warnings)
	}
}
