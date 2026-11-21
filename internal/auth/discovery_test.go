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
	for _, tt := range []struct{ body, want, wantWithDevice string }{
		{`{"authMode":"loopback"}`, "loopback", ""},
		{`{"authMode":"device"}`, "", "device"},
		{`{"authMethods":["loopback","device"],"preferredAuthMethod":"device","authMode":"device"}`, "loopback", "device"},
		{`{"authMethods":["loopback","device"],"preferredAuthMethod":"loopback"}`, "loopback", "device"},
		{`{"authMethods":["future","loopback"],"preferredAuthMethod":"future"}`, "loopback", ""},
		{`{"authMethods":["device"]}`, "", "device"},
		{`{"authMethods":["future"],"authMode":"loopback"}`, "", ""},
		{`{"authMethods":[],"authMode":"loopback"}`, "", ""},
		{`{"authMethods":["loopback"],"preferredAuthMethod":"device"}`, "", ""},
		{`{"authMode":"unknown"}`, "", ""},
		{`{"authMode":"browser"}`, "", ""},
		{`{"authMethods":["browser"],"preferredAuthMethod":"browser"}`, "", ""},
		{`{"authMethods":["browser","device"],"preferredAuthMethod":"browser"}`, "", "device"},
		{`{}`, "", ""},
	} {
		t.Run(tt.body, func(t *testing.T) {
			var d Discovery
			if err := json.Unmarshal([]byte(tt.body), &d); err != nil {
				t.Fatal(err)
			}
			got, err := d.Method(false)
			if got != tt.want || (err != nil) != (tt.want == "") {
				t.Fatalf("Method(false) = %q, %v", got, err)
			}
			got, err = d.Method(true)
			if got != tt.wantWithDevice || (err != nil) != (tt.wantWithDevice == "") {
				t.Fatalf("Method(true) = %q, %v", got, err)
			}
		})
	}
}

func TestDiscoveryNeverPicksDeviceSignInUnasked(t *testing.T) {
	for _, d := range []Discovery{
		{AuthMode: "device"},
		{AuthMethods: []string{"device"}, PreferredAuthMethod: "device"},
		{AuthMethods: []string{"loopback", "device"}, PreferredAuthMethod: "device"},
		{AuthMethods: []string{"browser", "device"}, PreferredAuthMethod: "device"},
	} {
		if method, _ := d.Method(false); method == authMethodDevice {
			t.Fatalf("%+v: device sign-in was picked without --device", d)
		}
	}
	if _, err := (Discovery{AuthMode: "device"}).Method(false); !errors.Is(err, errDeviceNeedsOptIn) {
		t.Fatalf("device-only server error = %v, want the --device hint", err)
	}
	if _, err := (Discovery{AuthMode: "loopback"}).Method(true); !errors.Is(err, errDeviceNotOffered) {
		t.Fatalf("--device against a server without device sign-in = %v", err)
	}
	if _, err := (Discovery{AuthMode: "browser"}).Method(true); !errors.Is(err, errLegacyServer) {
		t.Fatalf("--device against a legacy server = %v, want the update hint", err)
	}
}

func TestDiscoveryErrorsDoNotStartAuthentication(t *testing.T) {
	for _, body := range []string{`{`, `null`, `{}`, `{"authMethods":"loopback"}`, `{"authMode":"loopback"} {}`, `{"authMode":"loopback","baseUrl":"https://:443"}`, "http-error"} {
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
	for _, method := range []string{"loopback", "device"} {
		t.Run(method, func(t *testing.T) {
			deviceRequested := method == "device"
			keyring.MockInit()
			t.Setenv("HOME", t.TempDir())
			oldLoopback, oldDevice := loopbackToken, deviceToken
			t.Cleanup(func() { loopbackToken, deviceToken = oldLoopback, oldDevice })
			calls := []string{}
			loopbackToken = func(*config.ClientConfig, context.Context) (string, error) {
				calls = append(calls, "loopback")
				return "", errors.New("network failure")
			}
			deviceToken = func(*config.ClientConfig, context.Context) (string, error) {
				calls = append(calls, "device")
				return "", errors.New("denied")
			}
			ctx := WithDiscovery(t.Context(), "https://example.com", Discovery{AuthMethods: []string{"loopback", "device"}, PreferredAuthMethod: "device"})
			ctx = WithDeviceSignIn(ctx, deviceRequested)
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
	ctx := WithDiscovery(t.Context(), server.URL, Discovery{AuthMode: "loopback"})
	method, err := discoverMethod(ctx, server.URL)
	if err != nil || method != "loopback" || requests != 0 {
		t.Fatalf("reused discovery = %q, %v; requests = %d", method, err, requests)
	}
	ctx = WithDeviceSignIn(WithDiscovery(t.Context(), "https://other.example", Discovery{AuthMode: "loopback"}), true)
	method, err = discoverMethod(ctx, server.URL)
	if err != nil || method != "device" || requests != 1 {
		t.Fatalf("fresh discovery = %q, %v; requests = %d", method, err, requests)
	}
}

func TestDeviceOnlyServerNeedsTheDeviceFlag(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/cli-config" {
			t.Errorf("unexpected auth request: %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"authMethods":["browser","device"],"preferredAuthMethod":"device","authMode":"device"}`)
	}))
	defer server.Close()
	if _, err := Discover(t.Context(), server.URL); err != nil {
		t.Fatalf("Discover refused a device-only server: %v", err)
	}
	_, err := InitAuth(testAuthConfig(server.URL), t.Context(), true)
	if !errors.Is(err, errDeviceNeedsOptIn) {
		t.Fatalf("InitAuth error = %v, want the --device hint", err)
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

func TestDiscoveryNamesServersThatOnlyOfferTheRemovedBrowserFlow(t *testing.T) {
	_, err := Discovery{AuthMode: "browser"}.Method(false)
	if !errors.Is(err, errLegacyServer) {
		t.Fatalf("Method error = %v, want the update hint", err)
	}
}
