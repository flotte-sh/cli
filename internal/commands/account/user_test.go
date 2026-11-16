package account

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/config"
	"github.com/zalando/go-keyring"
)

func TestLoginAcceptsValidCachedSession(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	if err := auth.SaveToken("cached-token"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/me" || r.Header.Get("X-flotte-token") != "cached-token" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"authenticated":true,"email":"user@example.com"}`)
	}))
	defer server.Close()

	stdout, stderr, err := executeLogin(t, server.URL)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if !strings.Contains(stdout, "Logged in as user@example.com") || !strings.Contains(stdout, "Successfully authenticated.") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestLoginPreservesCachedSessionWhenValidationFails(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	if err := auth.SaveToken("cached-token"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, _, err := executeLogin(t, server.URL)
	if err == nil || !strings.Contains(err.Error(), "failed to validate cached session") {
		t.Fatalf("login error = %v", err)
	}
	got, loadErr := auth.LoadToken()
	if loadErr != nil {
		t.Fatalf("LoadToken: %v", loadErr)
	}
	if got != "cached-token" {
		t.Fatalf("cached token = %q, want %q", got, "cached-token")
	}
}

func TestLoginReauthenticatesStaleCachedSession(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	if err := auth.SaveToken("stale-token"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/cli-config":
			fmt.Fprint(w, `{"authMode":"browser"}`)
		case "/auth/me":
			if r.Header.Get("X-flotte-token") == "fresh-token" {
				fmt.Fprint(w, `{"authenticated":true,"email":"fresh@example.com"}`)
				return
			}
			fmt.Fprint(w, `{"authenticated":false}`)
		case "/auth/cli/token":
			if r.PostFormValue("code") != "loopback-code" || r.PostFormValue("code_verifier") == "" {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `{"access_token":"fresh-token","token_type":"Bearer","expires_in":3600}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	signInThroughLoopback := func(loginURL string) error {
		request, err := url.Parse(loginURL)
		if err != nil {
			return err
		}
		response := url.Values{"code": {"loopback-code"}, "state": {request.Query().Get("state")}, "iss": {server.URL}}
		go func() {
			resp, err := http.Get(request.Query().Get("redirect_uri") + "?" + response.Encode())
			if err != nil {
				t.Errorf("loopback callback: %v", err)
				return
			}
			_ = resp.Body.Close()
		}()
		return nil
	}
	stdout, _, err := executeLoginContext(t, auth.WithBrowserOpener(t.Context(), signInThroughLoopback), server.URL)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !strings.Contains(stdout, "Logged in as fresh@example.com") || !strings.Contains(stdout, "Successfully authenticated.") {
		t.Fatalf("stdout = %q", stdout)
	}
	got, loadErr := auth.LoadToken()
	if loadErr != nil {
		t.Fatalf("LoadToken: %v", loadErr)
	}
	if got != "fresh-token" {
		t.Fatalf("cached token = %q, want %q", got, "fresh-token")
	}
}

func TestLoginDeletesSessionInvalidatedDuringIdentityLookup(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	if err := auth.SaveToken("cached-token"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprintf(w, `{"authenticated":%t}`, requests == 1)
	}))
	defer server.Close()

	_, _, err := executeLogin(t, server.URL)
	if err == nil || !strings.Contains(err.Error(), "session expired during login") {
		t.Fatalf("login error = %v", err)
	}
	if _, loadErr := auth.LoadToken(); loadErr == nil {
		t.Fatal("expired token was not deleted")
	}
}

func executeLogin(t *testing.T, serverURL string) (string, string, error) {
	t.Helper()
	return executeLoginContext(t, t.Context(), serverURL)
}

func executeLoginContext(t *testing.T, ctx context.Context, serverURL string) (string, string, error) {
	t.Helper()
	root := &Root{Config: &config.ClientConfig{FlotteUrl: serverURL}}
	cmd := NewLoginCmd(root)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.ExecuteContext(ctx)
	return stdout.String(), stderr.String(), err
}
