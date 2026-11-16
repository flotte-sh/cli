package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeAuthorizationServer struct {
	t            *testing.T
	server       *httptest.Server
	mu           sync.Mutex
	tokenForms   []url.Values
	tokenStatus  int
	tokenBody    string
	tokenHandler http.HandlerFunc
}

func newFakeAuthorizationServer(t *testing.T) *fakeAuthorizationServer {
	t.Helper()
	fake := &fakeAuthorizationServer{t: t, tokenStatus: http.StatusOK, tokenBody: `{"access_token":"session-handle","token_type":"Bearer","expires_in":3600}`}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+oauthTokenPath, func(w http.ResponseWriter, r *http.Request) {
		if fake.tokenHandler != nil {
			fake.tokenHandler(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("token request form: %v", err)
		}
		fake.mu.Lock()
		fake.tokenForms = append(fake.tokenForms, r.PostForm)
		fake.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(fake.tokenStatus)
		_, _ = w.Write([]byte(fake.tokenBody))
	})
	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeAuthorizationServer) forms() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.tokenForms...)
}

type browserVisit struct {
	redirectURI string
	state       string
	challenge   string
}

var testBrowserOpener func(string) error

func stubBrowser(t *testing.T, visit func(browserVisit)) {
	t.Helper()
	testBrowserOpener = func(loginURL string) error {
		parsed, err := url.Parse(loginURL)
		if err != nil {
			t.Errorf("login URL: %v", err)
			return err
		}
		query := parsed.Query()
		if parsed.Path != oauthAuthorizePath || query.Get("response_type") != "code" || query.Get("client_id") != oauthClientID || query.Get("code_challenge_method") != "S256" {
			t.Errorf("unexpected authorization request: %s", loginURL)
		}
		go visit(browserVisit{redirectURI: query.Get("redirect_uri"), state: query.Get("state"), challenge: query.Get("code_challenge")})
		return nil
	}
	t.Cleanup(func() { testBrowserOpener = nil })
}

func loopbackGet(t *testing.T, target string) *http.Response {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(target)
	if err != nil {
		t.Errorf("loopback request: %v", err)
		return nil
	}
	_ = resp.Body.Close()
	return resp
}

func callbackURL(visit browserVisit, params url.Values) string {
	return visit.redirectURI + "?" + params.Encode()
}

func runBrowserFlow(t *testing.T, serverURL string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(WithPresentation(context.Background(), &bytes.Buffer{}, true), 10*time.Second)
	defer cancel()
	ctx = WithBrowserOpener(ctx, testBrowserOpener)
	return GetTokenFromBrowserFlow(testAuthConfig(serverURL), ctx)
}

func TestBrowserFlowRedeemsTheCodeItReceivedOnLoopback(t *testing.T) {
	fake := newFakeAuthorizationServer(t)
	var seen browserVisit
	stubBrowser(t, func(visit browserVisit) {
		seen = visit
		resp := loopbackGet(t, callbackURL(visit, url.Values{"code": {"auth-code"}, "state": {visit.state}, "iss": {fake.server.URL}}))
		if resp != nil && (resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != loopbackDonePath) {
			t.Errorf("callback answered %d to %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	token, err := runBrowserFlow(t, fake.server.URL)
	if err != nil {
		t.Fatalf("GetTokenFromBrowserFlow: %v", err)
	}
	if token != "session-handle" {
		t.Fatalf("token = %q", token)
	}

	redirect, err := url.Parse(seen.redirectURI)
	if err != nil || redirect.Scheme != "http" || redirect.Hostname() != "127.0.0.1" || redirect.Path != loopbackCallbackPath || redirect.Port() == "" {
		t.Fatalf("redirect URI is not an IP-literal loopback callback: %q", seen.redirectURI)
	}
	forms := fake.forms()
	if len(forms) != 1 {
		t.Fatalf("token requests = %d", len(forms))
	}
	form := forms[0]
	digest := sha256.Sum256([]byte(form.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(digest[:]) != seen.challenge {
		t.Fatal("code_verifier does not match the code_challenge sent to the authorization endpoint")
	}
	if len(form.Get("code_verifier")) < 43 || len(seen.state) < 43 {
		t.Fatalf("verifier or state too short: %d, %d", len(form.Get("code_verifier")), len(seen.state))
	}
	for key, want := range map[string]string{"grant_type": "authorization_code", "code": "auth-code", "client_id": oauthClientID, "redirect_uri": seen.redirectURI} {
		if form.Get(key) != want {
			t.Fatalf("token request %s = %q, want %q", key, form.Get(key), want)
		}
	}
}

func TestBrowserFlowKeepsWaitingAfterForeignLoopbackRequests(t *testing.T) {
	fake := newFakeAuthorizationServer(t)
	stubBrowser(t, func(visit browserVisit) {
		redirect, _ := url.Parse(visit.redirectURI)
		for name, request := range map[string]func() *http.Response{
			"wrong state": func() *http.Response {
				return loopbackGet(t, callbackURL(visit, url.Values{"code": {"attacker-code"}, "state": {"guess"}, "iss": {fake.server.URL}}))
			},
			"missing state": func() *http.Response {
				return loopbackGet(t, callbackURL(visit, url.Values{"error": {"access_denied"}, "iss": {fake.server.URL}}))
			},
			"other path": func() *http.Response { return loopbackGet(t, "http://"+redirect.Host+"/") },
			"rebound host": func() *http.Response {
				req, _ := http.NewRequest(http.MethodGet, callbackURL(visit, url.Values{"code": {"attacker-code"}, "state": {visit.state}, "iss": {fake.server.URL}}), nil)
				req.Host = "attacker.example"
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Errorf("rebound host request: %v", err)
					return nil
				}
				_ = resp.Body.Close()
				return resp
			},
			"post": func() *http.Response {
				resp, err := http.Post(callbackURL(visit, url.Values{"code": {"attacker-code"}, "state": {visit.state}, "iss": {fake.server.URL}}), "text/plain", nil)
				if err != nil {
					t.Errorf("post request: %v", err)
					return nil
				}
				_ = resp.Body.Close()
				return resp
			},
		} {
			if resp := request(); resp != nil && resp.StatusCode < 400 {
				t.Errorf("%s: loopback accepted the request with status %d", name, resp.StatusCode)
			}
		}
		loopbackGet(t, callbackURL(visit, url.Values{"code": {"auth-code"}, "state": {visit.state}, "iss": {fake.server.URL}}))
	})

	token, err := runBrowserFlow(t, fake.server.URL)
	if err != nil || token != "session-handle" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
	if forms := fake.forms(); len(forms) != 1 || forms[0].Get("code") != "auth-code" {
		t.Fatalf("unexpected token requests: %v", forms)
	}
}

func TestBrowserFlowRejectsResponsesItMustNotRedeem(t *testing.T) {
	for _, test := range []struct {
		name    string
		params  func(visit browserVisit, issuer string) url.Values
		wantErr string
	}{
		{"other issuer", func(visit browserVisit, _ string) url.Values {
			return url.Values{"code": {"auth-code"}, "state": {visit.state}, "iss": {"https://attacker.example"}}
		}, "configured Flotte server"},
		{"missing issuer", func(visit browserVisit, _ string) url.Values {
			return url.Values{"code": {"auth-code"}, "state": {visit.state}}
		}, "configured Flotte server"},
		{"authorization error", func(visit browserVisit, issuer string) url.Values {
			return url.Values{"error": {"access_denied"}, "error_description": {"sign-in was\x1b[31m cancelled"}, "state": {visit.state}, "iss": {issuer}}
		}, "access_denied: sign-in was[31m cancelled"},
		{"missing code", func(visit browserVisit, issuer string) url.Values {
			return url.Values{"state": {visit.state}, "iss": {issuer}}
		}, "did not contain a code"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeAuthorizationServer(t)
			stubBrowser(t, func(visit browserVisit) {
				resp := loopbackGet(t, callbackURL(visit, test.params(visit, fake.server.URL)))
				if resp != nil && resp.Header.Get("Location") != loopbackFailedPath {
					t.Errorf("callback redirected to %q", resp.Header.Get("Location"))
				}
			})
			token, err := runBrowserFlow(t, fake.server.URL)
			if err == nil || token != "" || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("token = %q, err = %v, want error containing %q", token, err, test.wantErr)
			}
			if forms := fake.forms(); len(forms) != 0 {
				t.Fatalf("token endpoint was called: %v", forms)
			}
		})
	}
}

func TestBrowserFlowRejectsUnusableTokenResponses(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{"oauth error", http.StatusBadRequest, `{"error":"invalid_grant","error_description":"code expired"}`, "invalid_grant: code expired"},
		{"plain error", http.StatusBadGateway, `upstream`, "HTTP 502"},
		{"empty token", http.StatusOK, `{"access_token":"","token_type":"Bearer"}`, "empty token"},
		{"other token type", http.StatusOK, `{"access_token":"x","token_type":"mac"}`, "unsupported token type"},
		{"not json", http.StatusOK, `<html>`, "unreadable token response"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeAuthorizationServer(t)
			fake.tokenStatus, fake.tokenBody = test.status, test.body
			stubBrowser(t, func(visit browserVisit) {
				loopbackGet(t, callbackURL(visit, url.Values{"code": {"auth-code"}, "state": {visit.state}, "iss": {fake.server.URL}}))
			})
			token, err := runBrowserFlow(t, fake.server.URL)
			if err == nil || token != "" || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("token = %q, err = %v, want error containing %q", token, err, test.wantErr)
			}
		})
	}
}

func TestBrowserFlowDoesNotFollowTokenEndpointRedirects(t *testing.T) {
	var redirectedRequests int
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirectedRequests++ }))
	defer elsewhere.Close()
	fake := newFakeAuthorizationServer(t)
	fake.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}
	stubBrowser(t, func(visit browserVisit) {
		loopbackGet(t, callbackURL(visit, url.Values{"code": {"auth-code"}, "state": {visit.state}, "iss": {fake.server.URL}}))
	})
	if token, err := runBrowserFlow(t, fake.server.URL); err == nil || token != "" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
	if redirectedRequests != 0 {
		t.Fatal("the code and verifier were re-sent to a redirect target")
	}
}

func TestBrowserFlowStopsWhenTheContextEnds(t *testing.T) {
	fake := newFakeAuthorizationServer(t)
	stubBrowser(t, func(browserVisit) {})
	ctx, cancel := context.WithTimeout(WithPresentation(context.Background(), &bytes.Buffer{}, true), 50*time.Millisecond)
	defer cancel()
	ctx = WithBrowserOpener(ctx, testBrowserOpener)
	if token, err := GetTokenFromBrowserFlow(testAuthConfig(fake.server.URL), ctx); err == nil || token != "" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
}
