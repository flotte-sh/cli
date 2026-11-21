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

	var challenge atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/cli-config":
			fmt.Fprint(w, `{"authMode":"loopback"}`)
		case "/auth/me":
			if r.Header.Get("X-flotte-token") == "fresh-token" {
				fmt.Fprint(w, `{"authenticated":true,"email":"fresh@example.com"}`)
				return
			}
			fmt.Fprint(w, `{"authenticated":false}`)
		case "/auth/cli/token":
			sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
			if r.PostFormValue("code") != "issued-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge.Load() {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `{"access_token":"fresh-token","token_type":"Bearer"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	stdout, _, err := executeLoginInBrowser(t, server.URL, func(loginURL string) {
		parsed, parseErr := url.Parse(loginURL)
		if parseErr != nil {
			t.Errorf("login URL: %v", parseErr)
			return
		}
		query := parsed.Query()
		challenge.Store(query.Get("code_challenge"))
		resp, getErr := http.Get(query.Get("redirect_uri") + "?" + url.Values{"code": {"issued-code"}, "state": {query.Get("state")}}.Encode())
		if getErr != nil {
			t.Errorf("deliver sign-in response: %v", getErr)
			return
		}
		_ = resp.Body.Close()
	})
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

func TestLoginUsesDeviceSignInOnlyWithTheDeviceFlag(t *testing.T) {
	for _, tt := range []struct {
		name       string
		args       []string
		wantDevice bool
	}{
		{"without the flag", nil, false},
		{"with the flag", []string{"--device"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			t.Setenv("HOME", t.TempDir())
			var deviceStarts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/cli-config":
					fmt.Fprint(w, `{"authMethods":["browser","device"],"preferredAuthMethod":"device","authMode":"device"}`)
				case "/auth/cli/device/start":
					deviceStarts.Add(1)
					fmt.Fprint(w, `{"deviceCode":"device-code","userCode":"ABCD-EFGH","verificationUri":"https://idp.example/device","interval":0}`)
				case "/auth/cli/device/token":
					fmt.Fprint(w, `{"token":"device-session","pending":false}`)
				case "/auth/me":
					fmt.Fprintf(w, `{"authenticated":%t,"email":"dev@example.com"}`, r.Header.Get("X-flotte-token") == "device-session")
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
				}
			}))
			defer server.Close()

			stdout, _, err := executeLogin(t, server.URL, tt.args...)
			if !tt.wantDevice {
				if err == nil || !strings.Contains(err.Error(), "flotte login --device") {
					t.Fatalf("login error = %v, want the --device hint", err)
				}
				if deviceStarts.Load() != 0 {
					t.Fatal("device sign-in started without --device")
				}
				return
			}
			if err != nil {
				t.Fatalf("login --device: %v", err)
			}
			if deviceStarts.Load() != 1 || !strings.Contains(stdout, "ABCD-EFGH") || !strings.Contains(stdout, "never enter a code that someone else sent you") {
				t.Fatalf("device starts = %d, output = %q", deviceStarts.Load(), stdout)
			}
		})
	}
}

func executeLogin(t *testing.T, serverURL string, args ...string) (string, string, error) {
	t.Helper()
	root := &Root{Config: &config.ClientConfig{FlotteUrl: serverURL}}
	cmd := NewLoginCmd(root)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(auth.WithPresentation(t.Context(), &stdout, true))
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
