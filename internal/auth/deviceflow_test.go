package auth

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeviceSignInKeepsPollingWhenRateLimited(t *testing.T) {
	oldMin, oldStep := deviceMinPollInterval, deviceSlowDownStep
	deviceMinPollInterval, deviceSlowDownStep = time.Millisecond, time.Millisecond
	t.Cleanup(func() { deviceMinPollInterval, deviceSlowDownStep = oldMin, oldStep })

	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/cli/device/start":
			fmt.Fprint(w, `{"deviceCode":"device-code","userCode":"ABCD-EFGH","verificationUri":"https://idp.example/device"}`)
		case "/auth/cli/device/token":
			polls++
			if polls == 1 {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			fmt.Fprint(w, `{"token":"device-session","pending":false}`)
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	token, err := GetTokenFromDeviceFlow(testAuthConfig(server.URL), WithPresentation(t.Context(), &out, true))
	if err != nil || token != "device-session" || polls != 2 {
		t.Fatalf("token = %q, err = %v, polls = %d", token, err, polls)
	}
	if !strings.Contains(out.String(), deviceCodeWarning) {
		t.Fatalf("output lacks the warning: %q", out.String())
	}
}

func TestDeviceSignInStopsOnOtherErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/cli/device/start" {
			fmt.Fprint(w, `{"deviceCode":"device-code","userCode":"ABCD-EFGH","verificationUri":"https://idp.example/device"}`)
			return
		}
		http.Error(w, `{"error":"device authorization denied"}`, http.StatusForbidden)
	}))
	defer server.Close()

	var out bytes.Buffer
	if _, err := GetTokenFromDeviceFlow(testAuthConfig(server.URL), WithPresentation(t.Context(), &out, true)); err == nil {
		t.Fatal("expected the denial to end the sign-in")
	}
}
