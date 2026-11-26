package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/flotte-sh/cli/internal/config"
	"github.com/zalando/go-keyring"
)

func TestDiscoverySelection(t *testing.T) {
	for _, tt := range []struct{ body, want string }{
		{`{"authMethods":["consent"]}`, "consent"},
		{`{"authMethods":["future","consent"]}`, "consent"},
		{`{"authMethods":["future"]}`, ""},
		{`{"authMethods":[]}`, ""},
		{`{}`, ""},
	} {
		t.Run(tt.body, func(t *testing.T) {
			var d Discovery
			if err := json.Unmarshal([]byte(tt.body), &d); err != nil {
				t.Fatal(err)
			}
			got, err := d.Method()
			if got != tt.want || (err != nil) != (tt.want == "") {
				t.Fatalf("Method = %q, %v", got, err)
			}
		})
	}
}

func TestDiscoveryErrorsDoNotStartAuthentication(t *testing.T) {
	for _, body := range []string{`{`, `null`, `{}`, `{"authMethods":"consent"}`, `{"authMethods":["consent"]} {}`, `{"authMethods":["consent"],"baseUrl":"https://:443"}`, "http-error"} {
		t.Run(body, func(t *testing.T) {
			keyring.MockInit()
			t.Setenv("HOME", t.TempDir())
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/cli-config" {
					t.Errorf("unexpected auth request: %s", r.URL.Path)
				}
				if body == "http-error" {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			if _, err := InitAuth(testAuthConfig(server.URL), t.Context(), true); err == nil {
				t.Fatal("expected discovery error")
			}
		})
	}
}

func TestAuthenticationDoesNotFallback(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	oldConsent := consentToken
	t.Cleanup(func() { consentToken = oldConsent })
	calls := 0
	consentToken = func(*config.ClientConfig, context.Context) (string, error) {
		calls++
		return "", errors.New("network failure")
	}
	ctx := WithDiscovery(t.Context(), "https://example.com", Discovery{AuthMethods: []string{"consent", "future"}})
	if _, err := InitAuth(testAuthConfig("https://example.com"), ctx, true); err == nil {
		t.Fatal("expected auth error")
	}
	if calls != 1 {
		t.Fatalf("consent sign-in calls = %d, want 1", calls)
	}
}

func TestNoninteractiveDoesNotDiscover(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected request") }))
	defer server.Close()
	if _, err := InitAuth(testAuthConfig(server.URL), t.Context(), false); err == nil {
		t.Fatal("expected missing session error")
	}
}

func TestDiscoveryReuseIsBoundToServer(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprint(w, `{"authMethods":["consent"]}`)
	}))
	defer server.Close()
	ctx := WithDiscovery(t.Context(), server.URL, Discovery{AuthMethods: []string{"consent"}})
	method, err := discoverMethod(ctx, server.URL)
	if err != nil || method != "consent" || requests != 0 {
		t.Fatalf("reused discovery = %q, %v; requests = %d", method, err, requests)
	}
	ctx = WithDiscovery(t.Context(), "https://other.example", Discovery{AuthMethods: []string{"consent"}})
	method, err = discoverMethod(ctx, server.URL)
	if err != nil || method != "consent" || requests != 1 {
		t.Fatalf("fresh discovery = %q, %v; requests = %d", method, err, requests)
	}
}

func TestDiscoveryNetworkAndCancellationErrors(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected request")
	}))
	server.Close()
	if _, err := InitAuth(testAuthConfig(server.URL), t.Context(), true); err == nil {
		t.Fatal("expected network error")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Discover(ctx, server.URL); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
