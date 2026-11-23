package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flotte-sh/cli/internal/config"
)

type consentTestServer struct {
	*httptest.Server
	answers []consentTestAnswer
	forms   []url.Values
	mu      sync.Mutex
}

type consentTestAnswer struct {
	body   string
	status int
}

func pendingAnswer() consentTestAnswer {
	return consentTestAnswer{status: http.StatusBadRequest, body: `{"error":"authorization_pending"}`}
}

func tokenAnswer(token string) consentTestAnswer {
	return consentTestAnswer{status: http.StatusOK, body: `{"access_token":"` + token + `","token_type":"Bearer"}`}
}

func newConsentTestServer(t *testing.T, answers ...consentTestAnswer) *consentTestServer {
	t.Helper()
	s := &consentTestServer{answers: answers}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/cli/token" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		s.mu.Lock()
		s.forms = append(s.forms, r.PostForm)
		answer := s.answers[min(len(s.forms), len(s.answers))-1]
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(answer.status)
		_, _ = w.Write([]byte(answer.body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *consentTestServer) requests() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]url.Values(nil), s.forms...)
}

func fastConsentPolling(t *testing.T) {
	t.Helper()
	original := consentPollInterval
	consentPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { consentPollInterval = original })
}

func startTestConsentLogin(t *testing.T, serverURL string) *consentLogin {
	t.Helper()
	login, err := startConsentLogin(serverURL)
	if err != nil {
		t.Fatalf("startConsentLogin: %v", err)
	}
	return login
}

func TestConsentLoginAuthorizeRequest(t *testing.T) {
	login := startTestConsentLogin(t, "https://flotte.example/base")
	parsed, err := url.Parse(login.authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "flotte.example" || parsed.Path != "/base/auth/cli/authorize" {
		t.Fatalf("authorize URL = %s", login.authorizeURL)
	}
	query := parsed.Query()
	sum := sha256.Sum256([]byte(login.verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	want := url.Values{
		"client_id":             {"flotte-cli"},
		"state":                 {login.state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if query.Encode() != want.Encode() {
		t.Fatalf("authorize query = %v, want %v", query, want)
	}
	if strings.Contains(login.authorizeURL, login.verifier) {
		t.Fatal("the verifier must never appear in the link")
	}
	if len(login.state) < 43 || len(login.verifier) < 43 {
		t.Fatalf("state or verifier too short: %d, %d", len(login.state), len(login.verifier))
	}

	other := startTestConsentLogin(t, "https://flotte.example/base")
	if other.state == login.state || other.verifier == login.verifier {
		t.Fatal("two sign-ins share a secret")
	}
}

func TestConsentLoginCollectsTheSessionOnceConfirmed(t *testing.T) {
	fastConsentPolling(t)
	server := newConsentTestServer(t, pendingAnswer(), pendingAnswer(), tokenAnswer("the-session"))
	login := startTestConsentLogin(t, server.URL)

	token, err := login.waitForSession(t.Context())
	if err != nil || token != "the-session" {
		t.Fatalf("waitForSession = %q, %v", token, err)
	}
	requests := server.requests()
	if len(requests) != 3 {
		t.Fatalf("requests = %d, want 3", len(requests))
	}
	want := url.Values{
		"grant_type":    {"urn:flotte:params:oauth:grant-type:cli-login"},
		"client_id":     {"flotte-cli"},
		"state":         {login.state},
		"code_verifier": {login.verifier},
	}
	for _, form := range requests {
		if form.Encode() != want.Encode() {
			t.Fatalf("token form = %v, want %v", form, want)
		}
	}
}

func TestConsentLoginRefusals(t *testing.T) {
	fastConsentPolling(t)
	for _, tc := range []struct {
		name      string
		body      string
		message   string
		status    int
		cancelled bool
	}{
		{name: "cancelled in the browser", status: 400, body: `{"error":"access_denied"}`, message: "cancelled", cancelled: true},
		{name: "failed on the server", status: 400, body: `{"error":"server_error"}`, message: "failed on the server"},
		{name: "rejected", status: 400, body: `{"error":"invalid_grant"}`, message: "rejected this sign-in"},
		{name: "older server", status: 400, body: `{"error":"unsupported_grant_type"}`, message: "update the Flotte server"},
		{name: "unknown error", status: 500, body: `oops`, message: "HTTP 500"},
		{name: "not json", status: 200, body: `<html>`, message: "invalid sign-in response"},
		{name: "empty token", status: 200, body: `{"access_token":"","token_type":"Bearer"}`, message: "invalid sign-in response"},
		{name: "token with a line break", status: 200, body: `{"access_token":"a\nb","token_type":"Bearer"}`, message: "invalid sign-in response"},
		{name: "other token type", status: 200, body: `{"access_token":"abc","token_type":"mac"}`, message: "invalid sign-in response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newConsentTestServer(t, pendingAnswer(), consentTestAnswer{status: tc.status, body: tc.body})
			login := startTestConsentLogin(t, server.URL)
			token, err := login.waitForSession(t.Context())
			if err == nil || token != "" {
				t.Fatalf("waitForSession = %q, %v", token, err)
			}
			if !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.message)
			}
			if errors.Is(err, errSignInCancelled) != tc.cancelled {
				t.Fatalf("cancelled = %v, want %v", errors.Is(err, errSignInCancelled), tc.cancelled)
			}
			if got := len(server.requests()); got != 2 {
				t.Fatalf("requests = %d, want the CLI to stop after the refusal", got)
			}
		})
	}
}

func TestConsentLoginNeverFollowsRedirectsWithTheVerifier(t *testing.T) {
	fastConsentPolling(t)
	var elsewhereHits int
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhereHits++ }))
	defer elsewhere.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	login := startTestConsentLogin(t, server.URL)
	if _, err := login.waitForSession(t.Context()); err == nil {
		t.Fatal("a redirect was accepted as an answer")
	}
	if elsewhereHits != 0 {
		t.Fatal("the verifier was sent to another address")
	}
}

func TestConsentLoginSurvivesShortOutagesButNotLongOnes(t *testing.T) {
	fastConsentPolling(t)
	var mu sync.Mutex
	failures := 3
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		fail := failures > 0
		failures--
		mu.Unlock()
		if fail {
			hijacker, _ := w.(http.Hijacker)
			conn, _, _ := hijacker.Hijack()
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"after-outage","token_type":"Bearer"}`))
	}))
	defer server.Close()

	login := startTestConsentLogin(t, server.URL)
	token, err := login.waitForSession(t.Context())
	if err != nil || token != "after-outage" {
		t.Fatalf("waitForSession = %q, %v", token, err)
	}

	server.Close()
	if _, err := login.waitForSession(t.Context()); err == nil || !strings.Contains(err.Error(), "failed to reach the server") {
		t.Fatalf("waitForSession on a dead server = %v", err)
	}
}

func TestConsentLoginWaitsLongerWhenTheServerThrottles(t *testing.T) {
	fastConsentPolling(t)
	server := newConsentTestServer(t, consentTestAnswer{status: http.StatusTooManyRequests}, tokenAnswer("later"))
	login := startTestConsentLogin(t, server.URL)
	token, err := login.waitForSession(t.Context())
	if err != nil || token != "later" {
		t.Fatalf("waitForSession = %q, %v", token, err)
	}
}

func TestConsentLoginWaitHonoursCancellationAndTimeout(t *testing.T) {
	fastConsentPolling(t)
	server := newConsentTestServer(t, pendingAnswer())
	login := startTestConsentLogin(t, server.URL)

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(30*time.Millisecond, cancel)
	if _, err := login.waitForSession(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait = %v", err)
	}

	ctx, stop := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer stop()
	if _, err := login.waitForSession(ctx); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timed-out wait = %v", err)
	}
}

func TestConsentLoginRefusesServerURLsABrowserMustNotOpen(t *testing.T) {
	for _, serverURL := range []string{"", "javascript:alert(1)", "file:///etc/passwd", "ftp://flotte.example", "//flotte.example"} {
		login, err := startConsentLogin(serverURL)
		if err == nil {
			t.Errorf("startConsentLogin(%q) built %q", serverURL, login.authorizeURL)
		}
	}
}

func TestGetTokenFromConsentFlowEndToEnd(t *testing.T) {
	fastConsentPolling(t)
	server := newConsentTestServer(t, pendingAnswer(), tokenAnswer("end-to-end"))

	var opened string
	originalBrowser := openBrowser
	openBrowser = func(target string) error {
		opened = target
		return nil
	}
	t.Cleanup(func() { openBrowser = originalBrowser })

	var out bytes.Buffer
	ctx := WithPresentation(t.Context(), &out, true)
	token, err := GetTokenFromConsentFlow(&config.ClientConfig{FlotteUrl: server.URL}, ctx)
	if err != nil || token != "end-to-end" {
		t.Fatalf("GetTokenFromConsentFlow = %q, %v", token, err)
	}
	if !strings.HasPrefix(opened, server.URL+"/auth/cli/authorize?") {
		t.Fatalf("browser opened %q", opened)
	}
	state := server.requests()[0].Get("state")
	if !strings.Contains(opened, "state="+state) {
		t.Fatal("the terminal asked about another sign-in than the one it opened")
	}
	if !strings.Contains(out.String(), opened) {
		t.Fatalf("instructions = %q", out.String())
	}
	if strings.Contains(out.String(), server.requests()[0].Get("code_verifier")) {
		t.Fatal("the verifier was printed")
	}
}
