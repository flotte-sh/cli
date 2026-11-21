package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flotte-sh/cli/internal/config"
)

const (
	loopbackClientID           = "flotte-cli"
	loopbackAddress            = "127.0.0.1"
	loopbackCallbackPath       = "/callback"
	loopbackDonePath           = "/done"
	loopbackPortEnv            = "FLOTTE_LOGIN_PORT"
	loopbackMinPort            = 1024
	loopbackMaxPort            = 65535
	loopbackLoginTimeout       = 5 * time.Minute
	loopbackTokenTimeout       = 30 * time.Second
	loopbackDoneGrace          = 3 * time.Second
	loopbackDoneWait           = 45 * time.Second
	maxAuthorizationCodeLength = 512
	maxSessionTokenLength      = 4096
)

var (
	errLoopbackCancelled = errors.New("sign-in was cancelled in the browser")
	openBrowser          = startBrowser
)

type loopbackResult struct {
	err  error
	code string
}

// loopbackLogin is one sign-in attempt. The authorization code is delivered by
// the browser to a listener on 127.0.0.1, so it only ever reaches the computer
// the browser runs on, and it is worthless without the verifier kept here.
type loopbackLogin struct {
	outcomeErr   error
	listener     net.Listener
	server       *http.Server
	result       chan loopbackResult
	outcome      chan struct{}
	doneServed   chan struct{}
	authorizeURL string
	tokenURL     string
	redirectURI  string
	hostPort     string
	state        string
	verifier     string
	doneTicket   string
	accept       sync.Once
	finishOnce   sync.Once
	servedOnce   sync.Once
	port         int
}

func GetTokenFromLoopbackFlow(cfg *config.ClientConfig, ctx context.Context) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	waitCtx, stopWaitingForBrowser := context.WithTimeout(ctx, loopbackLoginTimeout)
	defer stopWaitingForBrowser()

	login, err := startLoopbackLogin(cfg.FlotteUrl)
	if err != nil {
		return "", err
	}
	defer login.close()

	printLoopbackInstructions(ctx, login, openBrowser(login.authorizeURL))
	stopHotkeys := startBrowserHotkeys(ctx, login.authorizeURL, presentationWriter(ctx), cancel)
	defer stopHotkeys()
	stopWaiting := startAuthorizationWait(presentationWriter(ctx))
	defer stopWaiting()

	code, err := login.waitForCode(waitCtx)
	if err != nil {
		login.finish(err)
		return "", err
	}
	token, err := login.redeem(ctx, code)
	login.finish(err)
	if err != nil {
		return "", err
	}
	return token, nil
}

func startLoopbackLogin(serverURL string) (*loopbackLogin, error) {
	authorizeEndpoint, err := config.JoinEndpoint(serverURL, "/auth/cli/authorize")
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	tokenURL, err := config.JoinEndpoint(serverURL, "/auth/cli/token")
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	state, err := randomURLToken()
	if err != nil {
		return nil, fmt.Errorf("failed to prepare sign-in: %w", err)
	}
	verifier, err := randomURLToken()
	if err != nil {
		return nil, fmt.Errorf("failed to prepare sign-in: %w", err)
	}
	doneTicket, err := randomURLToken()
	if err != nil {
		return nil, fmt.Errorf("failed to prepare sign-in: %w", err)
	}
	listenPort, err := loopbackListenPort()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(loopbackAddress, strconv.Itoa(listenPort)))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s for the sign-in response: %w", loopbackAddress, err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if port < loopbackMinPort {
		_ = listener.Close()
		return nil, fmt.Errorf("the system assigned the unusable port %d for the sign-in response", port)
	}

	login := &loopbackLogin{
		listener:    listener,
		tokenURL:    tokenURL,
		port:        port,
		hostPort:    net.JoinHostPort(loopbackAddress, strconv.Itoa(port)),
		state:       state,
		verifier:    verifier,
		doneTicket:  doneTicket,
		result:      make(chan loopbackResult, 1),
		outcome:     make(chan struct{}),
		doneServed:  make(chan struct{}),
		redirectURI: "http://" + net.JoinHostPort(loopbackAddress, strconv.Itoa(port)) + loopbackCallbackPath,
	}
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", loopbackClientID)
	query.Set("redirect_uri", login.redirectURI)
	query.Set("state", state)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	login.authorizeURL = authorizeEndpoint + "?" + query.Encode()

	login.server = &http.Server{
		Handler:           login,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      loopbackDoneWait + 15*time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() { _ = login.server.Serve(listener) }()
	return login, nil
}

func loopbackListenPort() (int, error) {
	raw := strings.TrimSpace(os.Getenv(loopbackPortEnv))
	if raw == "" {
		return 0, nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < loopbackMinPort || port > loopbackMaxPort {
		return 0, fmt.Errorf("%s must be a port between %d and %d", loopbackPortEnv, loopbackMinPort, loopbackMaxPort)
	}
	return port, nil
}

func randomURLToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (l *loopbackLogin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")

	// A request that names another host reached this port through DNS
	// rebinding or a proxy, not through the redirect from Flotte.
	if r.Host != l.hostPort {
		writeLoopbackPage(w, http.StatusMisdirectedRequest, "Request refused", "This address only accepts the sign-in response for the Flotte CLI.")
		return
	}
	if r.Method != http.MethodGet {
		header.Set("Allow", http.MethodGet)
		writeLoopbackPage(w, http.StatusMethodNotAllowed, "Request refused", "This address only accepts the sign-in response for the Flotte CLI.")
		return
	}
	switch r.URL.Path {
	case loopbackCallbackPath:
		l.handleCallback(w, r)
	case loopbackDonePath:
		l.handleDone(w, r)
	default:
		writeLoopbackPage(w, http.StatusNotFound, "Not found", "This address only accepts the sign-in response for the Flotte CLI.")
	}
}

// isBrowserNavigation refuses requests a web page makes in the background
// (images, scripts, fetch). The genuine response is a top-level redirect.
// Clients that send no fetch metadata are not affected.
func isBrowserNavigation(r *http.Request) bool {
	mode := r.Header.Get("Sec-Fetch-Mode")
	dest := r.Header.Get("Sec-Fetch-Dest")
	return (mode == "" || mode == "navigate") && (dest == "" || dest == "document")
}

func (l *loopbackLogin) handleCallback(w http.ResponseWriter, r *http.Request) {
	if !isBrowserNavigation(r) {
		writeLoopbackPage(w, http.StatusForbidden, "Request refused", "This address only accepts the sign-in response for the Flotte CLI.")
		return
	}
	query := r.URL.Query()
	states := query["state"]
	if len(states) != 1 || subtle.ConstantTimeCompare([]byte(states[0]), []byte(l.state)) != 1 {
		writeLoopbackPage(w, http.StatusBadRequest, "Request refused", "This response does not belong to the sign-in that is waiting in your terminal.")
		return
	}

	result := loopbackResult{}
	codes := query["code"]
	switch {
	case query.Has("error"):
		result.err = loopbackCallbackError(query.Get("error"))
	case len(codes) == 1 && codes[0] != "" && len(codes[0]) <= maxAuthorizationCodeLength:
		result.code = codes[0]
	default:
		result.err = errors.New("the server sent an invalid sign-in response")
	}

	accepted := false
	l.accept.Do(func() {
		accepted = true
		l.result <- result
	})
	if !accepted {
		writeLoopbackPage(w, http.StatusBadRequest, "Request refused", "This sign-in response was already used.")
		return
	}
	http.Redirect(w, r, loopbackDonePath+"?ticket="+l.doneTicket, http.StatusSeeOther)
}

func loopbackCallbackError(code string) error {
	if code == "access_denied" {
		return errLoopbackCancelled
	}
	return errors.New("the server reported a sign-in error")
}

func (l *loopbackLogin) handleDone(w http.ResponseWriter, r *http.Request) {
	tickets := r.URL.Query()["ticket"]
	if len(tickets) != 1 || subtle.ConstantTimeCompare([]byte(tickets[0]), []byte(l.doneTicket)) != 1 {
		writeLoopbackPage(w, http.StatusNotFound, "Not found", "This address only accepts the sign-in response for the Flotte CLI.")
		return
	}
	timeout := time.NewTimer(loopbackDoneWait)
	defer timeout.Stop()
	select {
	case <-l.outcome:
	case <-r.Context().Done():
		return
	case <-timeout.C:
		writeLoopbackPage(w, http.StatusOK, "Return to your terminal", "The Flotte CLI is still finishing the sign-in.")
		return
	}
	defer l.servedOnce.Do(func() { close(l.doneServed) })
	switch {
	case l.outcomeErr == nil:
		writeLoopbackPage(w, http.StatusOK, "Signed in", "The Flotte CLI is signed in. You can close this tab and return to your terminal.")
	case errors.Is(l.outcomeErr, errLoopbackCancelled):
		writeLoopbackPage(w, http.StatusOK, "Sign-in cancelled", "Nothing was shared with the Flotte CLI. You can close this tab.")
	default:
		writeLoopbackPage(w, http.StatusOK, "Sign-in failed", "The Flotte CLI could not complete the sign-in. Return to your terminal for details.")
	}
}

const loopbackPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Flotte CLI</title>
</head>
<body>
<h1>%s</h1>
<p>%s</p>
</body>
</html>
`

// writeLoopbackPage only ever receives fixed text, never request data.
func writeLoopbackPage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, loopbackPage, title, message)
}

func (l *loopbackLogin) waitForCode(ctx context.Context) (string, error) {
	select {
	case result := <-l.result:
		return result.code, result.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("sign-in timed out after %s - run the command again", loopbackLoginTimeout)
		}
		return "", ctx.Err()
	}
}

type loopbackTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type loopbackTokenError struct {
	Error string `json:"error"`
}

func (l *loopbackLogin) redeem(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", loopbackClientID)
	form.Set("code", code)
	form.Set("redirect_uri", l.redirectURI)
	form.Set("code_verifier", l.verifier)

	ctx, cancel := context.WithTimeout(ctx, loopbackTokenTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: loopbackTokenTimeout,
		// The request carries the code and its verifier; never resend it elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req) //#nosec G107,G704 -- the URL is the configured Flotte server
	if err != nil {
		return "", fmt.Errorf("failed to reach the server to complete sign-in: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return "", fmt.Errorf("failed to read the sign-in response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var tokenErr loopbackTokenError
		_ = json.Unmarshal(body, &tokenErr)
		if tokenErr.Error == "invalid_grant" {
			return "", errors.New("the server rejected the sign-in code - it expired or was already used; run the command again")
		}
		return "", fmt.Errorf("the server refused to complete sign-in (HTTP %d)", resp.StatusCode)
	}
	var token loopbackTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return "", errors.New("the server sent an invalid sign-in response")
	}
	if !isSessionToken(token.AccessToken) || !strings.EqualFold(token.TokenType, "Bearer") {
		return "", errors.New("the server sent an invalid sign-in response")
	}
	return token.AccessToken, nil
}

func isSessionToken(token string) bool {
	if token == "" || len(token) > maxSessionTokenLength {
		return false
	}
	for _, c := range []byte(token) {
		if c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}

// finish tells the browser tab how the sign-in ended and gives it a moment to
// load that page before the listener goes away.
func (l *loopbackLogin) finish(outcome error) {
	l.finishOnce.Do(func() {
		l.outcomeErr = outcome
		close(l.outcome)
		accepted := true
		l.accept.Do(func() { accepted = false })
		if !accepted {
			return
		}
		grace := time.NewTimer(loopbackDoneGrace)
		defer grace.Stop()
		select {
		case <-l.doneServed:
		case <-grace.C:
		}
	})
}

func (l *loopbackLogin) close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := l.server.Shutdown(ctx); err != nil {
		_ = l.server.Close()
	}
	_ = l.listener.Close()
}

func printLoopbackInstructions(ctx context.Context, login *loopbackLogin, launchErr error) {
	out := presentationWriter(ctx)
	if launchErr != nil {
		fmt.Fprintf(out, "Could not open the browser automatically.\nVisit: %s\n", login.authorizeURL)
		printLoopbackRemoteHint(out, login.port)
		return
	}
	fmt.Fprintln(out, "Browser opened. Complete sign-in in your browser.")
	if showLoginURL(ctx) {
		fmt.Fprintf(out, "Visit: %s\n", login.authorizeURL)
		printLoopbackRemoteHint(out, login.port)
	} else {
		fmt.Fprintln(out, "Press x to show the login link, or c to copy it.")
		fmt.Fprintln(out, "You can also cancel and rerun setup with --show-login-url.")
	}
}

func printLoopbackRemoteHint(out io.Writer, port int) {
	fmt.Fprintln(out, "The link only works in a browser on this computer.")
	fmt.Fprintf(out, "On a remote machine, forward the port first: ssh -L %d:127.0.0.1:%d <this-machine>\n", port, port)
}
