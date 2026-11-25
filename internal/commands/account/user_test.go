package account

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/config"
	"github.com/zalando/go-keyring"
)

func TestLoginAcceptsValidCachedSession(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/me" || r.Header.Get("X-flotte-token") != "cached-token" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"authenticated":true,"email":"user@example.com"}`)
	}))
	defer server.Close()
	if err := auth.SaveToken(server.URL, "cached-token"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	if err := auth.SaveToken(server.URL, "cached-token"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	_, _, err := executeLogin(t, server.URL)
	if err == nil || !strings.Contains(err.Error(), "failed to validate cached session") {
		t.Fatalf("login error = %v", err)
	}
	got, loadErr := auth.LoadToken(server.URL)
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

	var challenge, state atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/cli-config":
			fmt.Fprint(w, `{"authMode":"consent"}`)
		case "/auth/me":
			if r.Header.Get("X-flotte-token") == "fresh-token" {
				fmt.Fprint(w, `{"authenticated":true,"email":"fresh@example.com"}`)
				return
			}
			fmt.Fprint(w, `{"authenticated":false}`)
		case "/auth/cli/start":
			fmt.Fprint(w, `{"ticket":"1795651200.ticket"}`)
		case "/auth/cli/token":
			sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
			approved, _ := challenge.Load().(string)
			if approved == "" {
				http.Error(w, `{"error":"authorization_pending"}`, http.StatusBadRequest)
				return
			}
			if r.PostFormValue("state") != state.Load() || base64.RawURLEncoding.EncodeToString(sum[:]) != approved {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `{"access_token":"fresh-token","token_type":"Bearer"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	if err := auth.SaveToken(server.URL, "stale-token"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	stdout, _, err := executeLoginInBrowser(t, server.URL, func(loginURL string) {
		parsed, parseErr := url.Parse(loginURL)
		if parseErr != nil {
			t.Errorf("login URL: %v", parseErr)
			return
		}
		query := parsed.Query()
		state.Store(query.Get("state"))
		challenge.Store(query.Get("code_challenge"))
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !strings.Contains(stdout, "Logged in as fresh@example.com") || !strings.Contains(stdout, "Successfully authenticated.") {
		t.Fatalf("stdout = %q", stdout)
	}
	got, loadErr := auth.LoadToken(server.URL)
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
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprintf(w, `{"authenticated":%t}`, requests == 1)
	}))
	defer server.Close()
	if err := auth.SaveToken(server.URL, "cached-token"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	_, _, err := executeLogin(t, server.URL)
	if err == nil || !strings.Contains(err.Error(), "session expired during login") {
		t.Fatalf("login error = %v", err)
	}
	if _, loadErr := auth.LoadToken(server.URL); loadErr == nil {
		t.Fatal("expired token was not deleted")
	}
}

func executeLogin(t *testing.T, serverURL string) (string, string, error) {
	t.Helper()
	root := &Root{Config: &config.ClientConfig{FlotteUrl: serverURL}}
	cmd := NewLoginCmd(root)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.ExecuteContext(t.Context())
	return stdout.String(), stderr.String(), err
}

type loginOutput struct {
	visit   func(loginURL string)
	buf     bytes.Buffer
	mu      sync.Mutex
	visited bool
}

func (o *loginOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n, err := o.buf.Write(p)
	if !o.visited {
		for line := range strings.SplitSeq(o.buf.String(), "\n") {
			if loginURL, ok := strings.CutPrefix(line, "Visit: "); ok && strings.Contains(o.buf.String(), line+"\n") {
				o.visited = true
				go o.visit(loginURL)
				break
			}
		}
	}
	return n, err
}

func (o *loginOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

// executeLoginInBrowser runs the login command and hands the printed login
// link to visit, which plays the part of the user's browser.
func executeLoginInBrowser(t *testing.T, serverURL string, visit func(loginURL string)) (string, string, error) {
	t.Helper()
	root := &Root{Config: &config.ClientConfig{FlotteUrl: serverURL}}
	cmd := NewLoginCmd(root)
	stdout := &loginOutput{visit: visit}
	var stderr bytes.Buffer
	cmd.SetOut(stdout)
	cmd.SetErr(&stderr)
	err := cmd.ExecuteContext(auth.WithPresentation(t.Context(), stdout, true))
	return stdout.String(), stderr.String(), err
}
