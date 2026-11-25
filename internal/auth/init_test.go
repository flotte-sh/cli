package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/flotte-sh/cli/internal/config"
	"github.com/zalando/go-keyring"
)

func TestInitAuthReturnsValidCachedSession(t *testing.T) {
	prepareTokenCache(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/me" || r.Header.Get("X-flotte-token") != "cached-token" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"authenticated":true}`)
	}))
	defer server.Close()
	cacheToken(t, server.URL, "cached-token")

	token, err := InitAuth(testAuthConfig(server.URL), t.Context(), true)
	if err != nil {
		t.Fatalf("InitAuth: %v", err)
	}
	if token != "cached-token" {
		t.Fatalf("token = %q, want %q", token, "cached-token")
	}
}

func TestInitAuthPreservesCachedSessionWhenValidationFails(t *testing.T) {
	prepareTokenCache(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cacheToken(t, server.URL, "cached-token")

	_, err := InitAuth(testAuthConfig(server.URL), t.Context(), true)
	if err == nil || !strings.Contains(err.Error(), "failed to validate cached session") {
		t.Fatalf("InitAuth error = %v", err)
	}
	token, loadErr := LoadToken(server.URL)
	if loadErr != nil {
		t.Fatalf("LoadToken: %v", loadErr)
	}
	if token != "cached-token" {
		t.Fatalf("token = %q, want %q", token, "cached-token")
	}
}

func TestInitAuthHonorsCanceledValidationContext(t *testing.T) {
	prepareTokenCache(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	cacheToken(t, server.URL, "cached-token")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := InitAuth(testAuthConfig(server.URL), ctx, true)
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("InitAuth error = %v", err)
	}
}

func TestInitAuthRejectsStaleSessionWithoutInteraction(t *testing.T) {
	prepareTokenCache(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"authenticated":false}`)
	}))
	defer server.Close()
	cacheToken(t, server.URL, "stale-token")

	_, err := InitAuth(testAuthConfig(server.URL), t.Context(), false)
	if err == nil || !strings.Contains(err.Error(), "interactive auth is disabled") {
		t.Fatalf("InitAuth error = %v", err)
	}
	if _, loadErr := LoadToken(server.URL); loadErr == nil {
		t.Fatal("stale token was not deleted")
	}
}

func TestInitAuthReauthenticatesStaleSession(t *testing.T) {
	prepareTokenCache(t)
	stubConsentToken(t, "fresh-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/cli-config" {
			fmt.Fprint(w, `{"authMode":"consent"}`)
			return
		}
		fmt.Fprintf(w, `{"authenticated":%t}`, r.Header.Get("X-flotte-token") == "fresh-token")
	}))
	defer server.Close()
	cacheToken(t, server.URL, "stale-token")

	token, err := InitAuth(testAuthConfig(server.URL), t.Context(), true)
	if err != nil {
		t.Fatalf("InitAuth: %v", err)
	}
	if token != "fresh-token" {
		t.Fatalf("token = %q, want %q", token, "fresh-token")
	}
	cached, loadErr := LoadToken(server.URL)
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
			prepareTokenCache(t)
			stubConsentToken(t, "fresh-token")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/cli-config" {
					fmt.Fprint(w, `{"authMode":"consent"}`)
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
			cacheToken(t, server.URL, "stale-token")

			token, err := InitAuth(testAuthConfig(server.URL), t.Context(), interactive)
			if !interactive {
				if err == nil || !strings.Contains(err.Error(), "interactive auth is disabled") {
					t.Fatalf("InitAuth error = %v", err)
				}
				if _, loadErr := LoadToken(server.URL); loadErr == nil {
					t.Fatal("stale token was not deleted")
				}
				return
			}
			if err != nil || token != "fresh-token" {
				t.Fatalf("InitAuth = %q, %v; want fresh-token", token, err)
			}
			cached, loadErr := LoadToken(server.URL)
			if loadErr != nil || cached != "fresh-token" {
				t.Fatalf("LoadToken = %q, %v; want fresh-token", cached, loadErr)
			}
		})
	}
}

func TestInitAuthCachesFreshSessionWhenValidationFails(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	stubConsentToken(t, "fresh-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/cli-config" {
			fmt.Fprint(w, `{"authMode":"consent"}`)
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := InitAuth(testAuthConfig(server.URL), t.Context(), true)
	if err == nil || !strings.Contains(err.Error(), "session validation failed") {
		t.Fatalf("InitAuth error = %v", err)
	}
	cached, loadErr := LoadToken(server.URL)
	if loadErr != nil {
		t.Fatalf("LoadToken: %v", loadErr)
	}
	if cached != "fresh-token" {
		t.Fatalf("cached token = %q, want %q", cached, "fresh-token")
	}
}

func prepareTokenCache(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
}

func cacheToken(t *testing.T, serverURL, token string) {
	t.Helper()
	if err := SaveToken(serverURL, token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
}

func testAuthConfig(serverURL string) *config.ClientConfig {
	return &config.ClientConfig{FlotteUrl: serverURL}
}

func stubConsentToken(t *testing.T, token string) {
	t.Helper()
	original := consentToken
	consentToken = func(*config.ClientConfig, context.Context) (string, error) {
		return token, nil
	}
	t.Cleanup(func() {
		consentToken = original
	})
}

func TestInitAuthNeverSendsACachedSessionToAnotherServer(t *testing.T) {
	for _, test := range []struct {
		name  string
		cache func(t *testing.T)
	}{
		{name: "session of another server", cache: func(t *testing.T) {
			cacheToken(t, "https://flotte.example.com", "other-server-token")
		}},
		{name: "session saved without its server", cache: func(t *testing.T) {
			if err := keyring.Set(keyringService, keyringUser, "other-server-token"); err != nil {
				t.Fatalf("keyring.Set: %v", err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepareTokenCache(t)
			test.cache(t)
			stubConsentToken(t, "fresh-token")
			var leaked, requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if strings.Contains(fmt.Sprint(r.Header, r.URL), "other-server-token") {
					leaked.Add(1)
				}
				if r.URL.Path == "/.well-known/cli-config" {
					fmt.Fprint(w, `{"authMode":"consent"}`)
					return
				}
				fmt.Fprintf(w, `{"authenticated":%t}`, r.Header.Get("X-flotte-token") == "fresh-token")
			}))
			defer server.Close()

			if _, err := InitAuth(testAuthConfig(server.URL), t.Context(), false); err == nil || !strings.Contains(err.Error(), "interactive auth is disabled") {
				t.Fatalf("InitAuth without interaction = %v", err)
			}
			if requests.Load() != 0 {
				t.Fatalf("the server received %d requests although no session belongs to it", requests.Load())
			}

			token, err := InitAuth(testAuthConfig(server.URL), t.Context(), true)
			if err != nil || token != "fresh-token" {
				t.Fatalf("InitAuth = %q, %v; want a fresh sign-in", token, err)
			}
			if leaked.Load() != 0 {
				t.Fatal("the session of another server was sent to this server")
			}
			session, err := LoadSession()
			if err != nil || session.Token != "fresh-token" || session.Server != server.URL {
				t.Fatalf("cached session = %+v, %v", session, err)
			}
		})
	}
}
