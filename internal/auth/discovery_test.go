package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/flotte-sh/flotte-cli/internal/config"
	"github.com/zalando/go-keyring"
)

func TestDiscoverySelection(t *testing.T) {
	for _, tt := range []struct{ body, want string }{
		{`{"authMode":"browser"}`, "browser"},
		{`{"authMode":"device"}`, "device"},
		{`{"authMethods":["browser","device"],"preferredAuthMethod":"device","authMode":"browser"}`, "device"},
		{`{"authMethods":["future","browser"],"preferredAuthMethod":"future"}`, "browser"},
		{`{"authMethods":["device"]}`, "device"},
		{`{"authMethods":["future"],"authMode":"browser"}`, ""},
		{`{"authMethods":[],"authMode":"browser"}`, ""},
		{`{"authMethods":["browser"],"preferredAuthMethod":"device"}`, ""},
		{`{"authMode":"unknown"}`, ""},
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
	for _, body := range []string{`{`, `null`, `{}`, `{"authMethods":"browser"}`, `{"authMode":"browser"} {}`, `{"authMode":"browser","baseUrl":"https://:443"}`, "http-error"} {
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
	for _, method := range []string{"browser", "device"} {
		t.Run(method, func(t *testing.T) {
			keyring.MockInit()
			t.Setenv("HOME", t.TempDir())
			oldBrowser, oldDevice := browserToken, deviceToken
			t.Cleanup(func() { browserToken, deviceToken = oldBrowser, oldDevice })
			calls := []string{}
			browserToken = func(*config.ClientConfig, context.Context) (string, error) {
				calls = append(calls, "browser")
				return "", errors.New("network failure")
			}
			deviceToken = func(*config.ClientConfig, context.Context) (string, error) {
				calls = append(calls, "device")
				return "", errors.New("denied")
			}
			ctx := WithDiscovery(t.Context(), "https://example.com", Discovery{AuthMethods: []string{"browser", "device"}, PreferredAuthMethod: method})
			if _, err := InitAuth(testAuthConfig("https://example.com"), ctx, true); err == nil {
				t.Fatal("expected auth error")
			}
			if len(calls) != 1 || calls[0] != method {
				t.Fatalf("calls = %v", calls)
			}
		})
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
		fmt.Fprint(w, `{"authMode":"device"}`)
	}))
	defer server.Close()
	ctx := WithDiscovery(t.Context(), server.URL, Discovery{AuthMode: "browser"})
	method, err := discoverMethod(ctx, server.URL)
	if err != nil || method != "browser" || requests != 0 {
		t.Fatalf("reused discovery = %q, %v; requests = %d", method, err, requests)
	}
	ctx = WithDiscovery(t.Context(), "https://other.example", Discovery{AuthMode: "browser"})
	method, err = discoverMethod(ctx, server.URL)
	if err != nil || method != "device" || requests != 1 {
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
