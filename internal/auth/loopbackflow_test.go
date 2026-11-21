package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flotte-sh/cli/internal/config"
)

type loopbackTestServer struct {
	*httptest.Server
	tokenRequests []url.Values
	respond       func(w http.ResponseWriter, form url.Values)
	mu            sync.Mutex
}

func newLoopbackTestServer(t *testing.T) *loopbackTestServer {
	t.Helper()
	s := &loopbackTestServer{}
	s.respond = func(w http.ResponseWriter, _ url.Values) {
		fmt.Fprint(w, `{"access_token":"session-token","token_type":"Bearer","expires_in":3600}`)
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/cli/token" || r.Method != http.MethodPost {
			t.Errorf("unexpected request from the CLI: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("token Content-Type = %q", got)
		}
		_ = r.ParseForm()
		s.mu.Lock()
		s.tokenRequests = append(s.tokenRequests, r.PostForm)
		respond := s.respond
		s.mu.Unlock()
		respond(w, r.PostForm)
	}))
	t.Cleanup(s.Close)
	return s
}

func startTestLoopbackLogin(t *testing.T, serverURL string) *loopbackLogin {
	t.Helper()
	login, err := startLoopbackLogin(serverURL)
	if err != nil {
		t.Fatalf("startLoopbackLogin: %v", err)
	}
	t.Cleanup(login.close)
	return login
}

func loopbackGet(t *testing.T, target string, mutate func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(req)
	}
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (l *loopbackLogin) callbackURL(query url.Values) string {
	return l.redirectURI + "?" + query.Encode()
}

func TestLoopbackLoginAuthorizeRequest(t *testing.T) {
	login := startTestLoopbackLogin(t, "https://flotte.example/base")

	parsed, err := url.Parse(login.authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != "https://flotte.example/base/auth/cli/authorize" {
		t.Fatalf("authorize endpoint = %q", got)
	}
	q := parsed.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != "flotte-cli" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("unexpected authorize parameters: %v", q)
	}
	if want := fmt.Sprintf("http://127.0.0.1:%d/callback", login.port); q.Get("redirect_uri") != want {
		t.Fatalf("redirect_uri = %q, want %q", q.Get("redirect_uri"), want)
	}
	sum := sha256.Sum256([]byte(login.verifier))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("code_challenge is not the S256 hash of the verifier")
	}
	if len(q.Get("state")) < 43 || len(login.verifier) < 43 {
		t.Fatal("state or verifier carries less than 256 bits")
	}
	if strings.Contains(login.authorizeURL, login.verifier) {
		t.Fatal("the verifier leaked into the authorize URL")
	}
	if host, _, _ := net.SplitHostPort(login.listener.Addr().String()); host != "127.0.0.1" {
		t.Fatalf("listener is bound to %q, want 127.0.0.1 only", host)
	}

	other := startTestLoopbackLogin(t, "https://flotte.example/base")
	if other.state == login.state || other.verifier == login.verifier {
		t.Fatal("two sign-ins share a state or verifier")
	}
}

func TestLoopbackLoginRedeemsTheCodeItReceives(t *testing.T) {
	server := newLoopbackTestServer(t)
	login := startTestLoopbackLogin(t, server.URL)

	resp := loopbackGet(t, login.callbackURL(url.Values{"code": {"the-code"}, "state": {login.state}}), nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/done?ticket="+login.doneTicket {
		t.Fatalf("callback = %d %q, want a redirect to /done", resp.StatusCode, resp.Header.Get("Location"))
	}
	for name, want := range map[string]string{"Cache-Control": "no-store", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("Content-Security-Policy = %q", resp.Header.Get("Content-Security-Policy"))
	}

	code, err := login.waitForCode(t.Context())
	if err != nil || code != "the-code" {
		t.Fatalf("waitForCode = %q, %v", code, err)
	}
	token, err := login.redeem(t.Context(), code)
	if err != nil || token != "session-token" {
		t.Fatalf("redeem = %q, %v", token, err)
	}
	if len(server.tokenRequests) != 1 {
		t.Fatalf("token endpoint was called %d times", len(server.tokenRequests))
	}
	form := server.tokenRequests[0]
	if form.Get("grant_type") != "authorization_code" || form.Get("client_id") != "flotte-cli" || form.Get("code") != "the-code" ||
		form.Get("redirect_uri") != login.redirectURI || form.Get("code_verifier") != login.verifier {
		t.Fatalf("unexpected token request: %v", form)
	}

	done := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + login.hostPort + "/done?ticket=" + login.doneTicket)
		if err != nil {
			done <- err.Error()
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		done <- string(body)
	}()
	login.finish(nil)
	if body := <-done; !strings.Contains(body, "Signed in") {
		t.Fatalf("done page = %q", body)
	}
}

func TestLoopbackLoginIgnoresRequestsThatAreNotTheResponse(t *testing.T) {
	login := startTestLoopbackLogin(t, "https://flotte.example")
	base := "http://" + login.hostPort

	refusals := []struct {
		name   string
		target string
		mutate func(*http.Request)
		status int
	}{
		{"wrong state", login.callbackURL(url.Values{"code": {"evil"}, "state": {"guess"}}), nil, http.StatusBadRequest},
		{"missing state", login.callbackURL(url.Values{"code": {"evil"}}), nil, http.StatusBadRequest},
		{"two states", login.callbackURL(url.Values{"code": {"evil"}, "state": {login.state, login.state}}), nil, http.StatusBadRequest},
		{"error with wrong state", login.callbackURL(url.Values{"error": {"access_denied"}, "state": {"guess"}}), nil, http.StatusBadRequest},
		{"rebound host", login.callbackURL(url.Values{"code": {"evil"}, "state": {login.state}}), func(r *http.Request) { r.Host = "attacker.example:" + strconv.Itoa(login.port) }, http.StatusMisdirectedRequest},
		{"localhost host", login.callbackURL(url.Values{"code": {"evil"}, "state": {login.state}}), func(r *http.Request) { r.Host = "localhost:" + strconv.Itoa(login.port) }, http.StatusMisdirectedRequest},
		{"post", login.callbackURL(url.Values{"code": {"evil"}, "state": {login.state}}), func(r *http.Request) { r.Method = http.MethodPost }, http.StatusMethodNotAllowed},
		{"background image request", login.callbackURL(url.Values{"code": {"evil"}, "state": {login.state}}), func(r *http.Request) {
			r.Header.Set("Sec-Fetch-Mode", "no-cors")
			r.Header.Set("Sec-Fetch-Dest", "image")
		}, http.StatusForbidden},
		{"background fetch", login.callbackURL(url.Values{"error": {"access_denied"}, "state": {login.state}}), func(r *http.Request) {
			r.Header.Set("Sec-Fetch-Mode", "cors")
			r.Header.Set("Sec-Fetch-Dest", "empty")
		}, http.StatusForbidden},
		{"done page without ticket", base + "/done", nil, http.StatusNotFound},
		{"done page with wrong ticket", base + "/done?ticket=guess", nil, http.StatusNotFound},
		{"other path", base + "/callback/extra?state=" + login.state + "&code=evil", nil, http.StatusNotFound},
		{"root", base + "/", nil, http.StatusNotFound},
	}
	for _, refusal := range refusals {
		resp := loopbackGet(t, refusal.target, refusal.mutate)
		if resp.StatusCode != refusal.status {
			t.Errorf("%s: status = %d, want %d", refusal.name, resp.StatusCode, refusal.status)
		}
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "evil") || strings.Contains(string(body), "guess") {
			t.Errorf("%s: request data was reflected: %s", refusal.name, body)
		}
	}
	select {
	case result := <-login.result:
		t.Fatalf("a refused request ended the sign-in: %+v", result)
	default:
	}

	resp := loopbackGet(t, login.callbackURL(url.Values{"code": {"real"}, "state": {login.state}}), func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("genuine callback after refused requests = %d", resp.StatusCode)
	}
	if code, err := login.waitForCode(t.Context()); err != nil || code != "real" {
		t.Fatalf("waitForCode = %q, %v", code, err)
	}
	resp = loopbackGet(t, login.callbackURL(url.Values{"code": {"second"}, "state": {login.state}}), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("second callback = %d, want 400", resp.StatusCode)
	}
}

func TestLoopbackLoginCallbackErrors(t *testing.T) {
	cases := []struct {
		name      string
		query     url.Values
		cancelled bool
	}{
		{"cancelled in browser", url.Values{"error": {"access_denied"}}, true},
		{"other error", url.Values{"error": {"server_error"}}, false},
		{"error wins over code", url.Values{"error": {"access_denied"}, "code": {"x"}}, true},
		{"no code", url.Values{}, false},
		{"two codes", url.Values{"code": {"a", "b"}}, false},
		{"oversized code", url.Values{"code": {strings.Repeat("c", maxAuthorizationCodeLength+1)}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			login := startTestLoopbackLogin(t, "https://flotte.example")
			tc.query.Set("state", login.state)
			_ = loopbackGet(t, login.callbackURL(tc.query), nil)
			code, err := login.waitForCode(t.Context())
			if err == nil || code != "" {
				t.Fatalf("waitForCode = %q, %v, want an error", code, err)
			}
			if errors.Is(err, errLoopbackCancelled) != tc.cancelled {
				t.Fatalf("error = %v, cancelled = %v", err, tc.cancelled)
			}
		})
	}
}

func TestLoopbackLoginRedeemRefusals(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the code and verifier were resent to another server: %s", r.URL)
	}))
	defer elsewhere.Close()

	cases := []struct {
		name    string
		respond func(w http.ResponseWriter, form url.Values)
		want    string
	}{
		{"invalid grant", func(w http.ResponseWriter, _ url.Values) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
		}, "rejected the sign-in code"},
		{"server error", func(w http.ResponseWriter, _ url.Values) { w.WriteHeader(http.StatusInternalServerError) }, "HTTP 500"},
		{"redirect", func(w http.ResponseWriter, _ url.Values) {
			w.Header().Set("Location", elsewhere.URL+"/auth/cli/token")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}, "HTTP 307"},
		{"empty token", func(w http.ResponseWriter, _ url.Values) { fmt.Fprint(w, `{"access_token":"","token_type":"Bearer"}`) }, "invalid sign-in response"},
		{"other token type", func(w http.ResponseWriter, _ url.Values) { fmt.Fprint(w, `{"access_token":"x","token_type":"mac"}`) }, "invalid sign-in response"},
		{"oversized token", func(w http.ResponseWriter, _ url.Values) {
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer"}`, strings.Repeat("t", maxSessionTokenLength+1))
		}, "invalid sign-in response"},
		{"token with control characters", func(w http.ResponseWriter, _ url.Values) {
			fmt.Fprint(w, `{"access_token":"abc\r\nX-Injected: 1","token_type":"Bearer"}`)
		}, "invalid sign-in response"},
		{"old response shape", func(w http.ResponseWriter, _ url.Values) { fmt.Fprint(w, `{"token":"x"}`) }, "invalid sign-in response"},
		{"not json", func(w http.ResponseWriter, _ url.Values) { fmt.Fprint(w, `<html>`) }, "invalid sign-in response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newLoopbackTestServer(t)
			server.respond = tc.respond
			login := startTestLoopbackLogin(t, server.URL)
			token, err := login.redeem(t.Context(), "code")
			if err == nil || token != "" || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("redeem = %q, %v, want an error containing %q", token, err, tc.want)
			}
			if strings.Contains(err.Error(), login.verifier) {
				t.Fatal("the verifier leaked into the error")
			}
		})
	}
}

func TestLoopbackLoginStopsListeningWhenItEnds(t *testing.T) {
	login, err := startLoopbackLogin("https://flotte.example")
	if err != nil {
		t.Fatal(err)
	}
	login.finish(errors.New("failed"))
	login.close()
	if conn, err := net.DialTimeout("tcp", login.hostPort, time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("the listener is still open after the sign-in ended")
	}
}

func TestLoopbackLoginWaitHonoursCancellation(t *testing.T) {
	login := startTestLoopbackLogin(t, "https://flotte.example")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := login.waitForCode(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForCode = %v, want context.Canceled", err)
	}
	expired, cancelExpired := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if _, err := login.waitForCode(expired); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("waitForCode = %v, want a timeout", err)
	}
}

func TestLoopbackLoginPortOverride(t *testing.T) {
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	t.Setenv(loopbackPortEnv, strconv.Itoa(port))
	login := startTestLoopbackLogin(t, "https://flotte.example")
	if login.port != port {
		t.Fatalf("port = %d, want %d", login.port, port)
	}
	if _, err := startLoopbackLogin("https://flotte.example"); err == nil {
		t.Fatal("a second sign-in shared a port that is already taken")
	}

	for _, invalid := range []string{"80", "0", "65536", "abc", "-1", "8080x"} {
		t.Setenv(loopbackPortEnv, invalid)
		if _, err := startLoopbackLogin("https://flotte.example"); err == nil {
			t.Errorf("%s=%q was accepted", loopbackPortEnv, invalid)
		}
	}
}

func TestLoopbackLoginRefusesServerURLsABrowserMustNotOpen(t *testing.T) {
	for _, serverURL := range []string{"file:///etc/passwd", "javascript:alert(1)", "ftp://flotte.example", `\\host\share\tool.exe`, "https://user:pw@flotte.example", ""} {
		login, err := startLoopbackLogin(serverURL)
		if err != nil {
			continue
		}
		login.close()
		if !strings.HasPrefix(login.authorizeURL, "https://") && !strings.HasPrefix(login.authorizeURL, "http://") {
			t.Errorf("server URL %q produced the login URL %q", serverURL, login.authorizeURL)
		}
		if strings.Contains(login.authorizeURL, "@") {
			t.Errorf("server URL %q kept user info: %q", serverURL, login.authorizeURL)
		}
	}
}

type loopbackTestBrowser struct {
	visit   func(loginURL string)
	buf     bytes.Buffer
	mu      sync.Mutex
	visited bool
}

func (b *loopbackTestBrowser) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.buf.Write(p)
	if !b.visited {
		for _, line := range strings.Split(b.buf.String(), "\n") {
			if loginURL, ok := strings.CutPrefix(line, "Visit: "); ok && strings.Contains(b.buf.String(), line+"\n") {
				b.visited = true
				go b.visit(loginURL)
				break
			}
		}
	}
	return n, err
}

func TestGetTokenFromLoopbackFlowEndToEnd(t *testing.T) {
	originalOpen := openBrowser
	t.Cleanup(func() { openBrowser = originalOpen })
	var opened string
	openBrowser = func(target string) error {
		opened = target
		return errors.New("no browser in tests")
	}

	server := newLoopbackTestServer(t)
	var challenge string
	server.respond = func(w http.ResponseWriter, form url.Values) {
		sum := sha256.Sum256([]byte(form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || form.Get("code") != "issued-code" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		fmt.Fprint(w, `{"access_token":"session-token","token_type":"Bearer"}`)
	}

	donePage := make(chan string, 1)
	browser := &loopbackTestBrowser{visit: func(loginURL string) {
		parsed, err := url.Parse(loginURL)
		if err != nil {
			donePage <- err.Error()
			return
		}
		q := parsed.Query()
		challenge = q.Get("code_challenge")
		resp, err := http.Get(q.Get("redirect_uri") + "?" + url.Values{"code": {"issued-code"}, "state": {q.Get("state")}}.Encode())
		if err != nil {
			donePage <- err.Error()
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		donePage <- string(body)
	}}

	ctx := WithPresentation(t.Context(), browser, false)
	token, err := GetTokenFromLoopbackFlow(&config.ClientConfig{FlotteUrl: server.URL}, ctx)
	if err != nil || token != "session-token" {
		t.Fatalf("GetTokenFromLoopbackFlow = %q, %v", token, err)
	}
	if !strings.HasPrefix(opened, server.URL+"/auth/cli/authorize?") {
		t.Fatalf("browser was opened on %q, want the configured server", opened)
	}
	if page := <-donePage; !strings.Contains(page, "Signed in") {
		t.Fatalf("browser ended on %q", page)
	}
	if strings.Contains(browser.buf.String(), "session-token") {
		t.Fatal("the session token was printed")
	}
}

func TestLoopbackLoginRedeemsACodeThatArrivesAtTheEndOfTheWait(t *testing.T) {
	originalOpen := openBrowser
	t.Cleanup(func() { openBrowser = originalOpen })
	openBrowser = func(string) error { return errors.New("no browser in tests") }

	server := newLoopbackTestServer(t)
	login := startTestLoopbackLogin(t, server.URL)
	expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := login.waitForCode(expired); err == nil {
		t.Fatal("expected the wait to time out")
	}
	if token, err := login.redeem(t.Context(), "code"); err != nil || token != "session-token" {
		t.Fatalf("redeem after the wait deadline = %q, %v", token, err)
	}
}
