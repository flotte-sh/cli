package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flotte-sh/cli/internal/config"
	"github.com/zalando/go-keyring"
)

func TestInitAuthReturnsValidCachedSession(t *testing.T) {
	prepareCachedToken(t, "cached-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/me" || r.Header.Get("X-flotte-token") != "cached-token" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"authenticated":true}`)
	}))
	defer server.Close()

	token, err := InitAuth(testAuthConfig(server.URL), t.Context(), true)
	if err != nil {
		t.Fatalf("InitAuth: %v", err)
	}
	if token != "cached-token" {
		t.Fatalf("token = %q, want %q", token, "cached-token")
	}
}

func TestInitAuthPreservesCachedSessionWhenValidationFails(t *testing.T) {
	prepareCachedToken(t, "cached-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := InitAuth(testAuthConfig(server.URL), t.Context(), true)
	if err == nil || !strings.Contains(err.Error(), "failed to validate cached session") {
		t.Fatalf("InitAuth error = %v", err)
	}
	token, loadErr := LoadToken()
	if loadErr != nil {
		t.Fatalf("LoadToken: %v", loadErr)
	}
	if token != "cached-token" {
		t.Fatalf("token = %q, want %q", token, "cached-token")
	}
}

func TestInitAuthHonorsCanceledValidationContext(t *testing.T) {
	prepareCachedToken(t, "cached-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := InitAuth(testAuthConfig(server.URL), ctx, true)
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("InitAuth error = %v", err)
	}
}

func TestInitAuthRejectsStaleSessionWithoutInteraction(t *testing.T) {
	prepareCachedToken(t, "stale-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"authenticated":false}`)
	}))
	defer server.Close()

	_, err := InitAuth(testAuthConfig(server.URL), t.Context(), false)
	if err == nil || !strings.Contains(err.Error(), "interactive auth is disabled") {
		t.Fatalf("InitAuth error = %v", err)
	}
	if _, loadErr := LoadToken(); loadErr == nil {
		t.Fatal("stale token was not deleted")
	}
}

func TestInitAuthReauthenticatesStaleSession(t *testing.T) {
	prepareCachedToken(t, "stale-token")
	stubBrowserToken(t, "fresh-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/cli-config" {
			fmt.Fprint(w, `{"authMode":"browser"}`)
			return
		}
		fmt.Fprintf(w, `{"authenticated":%t}`, r.Header.Get("X-flotte-token") == "fresh-token")
	}))
	defer server.Close()

	token, err := InitAuth(testAuthConfig(server.URL), t.Context(), true)
	if err != nil {
		t.Fatalf("InitAuth: %v", err)
	}
	if token != "fresh-token" {
		t.Fatalf("token = %q, want %q", token, "fresh-token")
	}
	cached, loadErr := LoadToken()
	if loadErr != nil {
		t.Fatalf("LoadToken: %v", loadErr)
	}
	if cached != "fresh-token" {
		t.Fatalf("cached token = %q, want %q", cached, "fresh-token")
	}
}

func TestInitAuthRecoversFromUnauthorizedCachedSession(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		t.Run(fmt.Sprintf("interactive=%t", interactive), func(t *testing.T) {
			prepareCachedToken(t, "stale-token")
			stubBrowserToken(t, "fresh-token")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/cli-config" {
					fmt.Fprint(w, `{"authMode":"browser"}`)
					return
				}
				if r.Header.Get("X-flotte-token") == "stale-token" {
					w.WriteHeader(http.StatusUnauthorized)
					fmt.Fprint(w, `{"error":"authentication required"}`)
					return
				}
				fmt.Fprint(w, `{"authenticated":true}`)
			}))
			defer server.Close()

			token, err := InitAuth(testAuthConfig(server.URL), t.Context(), interactive)
			if !interactive {
				if err == nil || !strings.Contains(err.Error(), "interactive auth is disabled") {
					t.Fatalf("InitAuth error = %v", err)
				}
				if _, loadErr := LoadToken(); loadErr == nil {
					t.Fatal("stale token was not deleted")
				}
				return
			}
			if err != nil || token != "fresh-token" {
				t.Fatalf("InitAuth = %q, %v; want fresh-token", token, err)
			}
			cached, loadErr := LoadToken()
			if loadErr != nil || cached != "fresh-token" {
				t.Fatalf("LoadToken = %q, %v; want fresh-token", cached, loadErr)
			}
		})
	}
}

func TestInitAuthCachesFreshSessionWhenValidationFails(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	stubBrowserToken(t, "fresh-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/cli-config" {
			fmt.Fprint(w, `{"authMode":"browser"}`)
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := InitAuth(testAuthConfig(server.URL), t.Context(), true)
	if err == nil || !strings.Contains(err.Error(), "session validation failed") {
		t.Fatalf("InitAuth error = %v", err)
	}
	cached, loadErr := LoadToken()
	if loadErr != nil {
		t.Fatalf("LoadToken: %v", loadErr)
	}
	if cached != "fresh-token" {
		t.Fatalf("cached token = %q, want %q", cached, "fresh-token")
	}
}

func prepareCachedToken(t *testing.T, token string) {
	t.Helper()
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	if err := SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
}

func testAuthConfig(serverURL string) *config.ClientConfig {
	return &config.ClientConfig{FlotteUrl: serverURL}
}

func stubBrowserToken(t *testing.T, token string) {
	t.Helper()
	original := browserToken
	browserToken = func(*config.ClientConfig, context.Context) (string, error) {
		return token, nil
	}
	t.Cleanup(func() {
		browserToken = original
	})
}
