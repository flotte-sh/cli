package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/flotte-sh/cli/internal/config"
)

const (
	consentClientID          = "flotte-cli"
	consentGrantType         = "urn:flotte:params:oauth:grant-type:cli-login"
	consentLoginTimeout      = 5 * time.Minute
	consentRequestTimeout    = 15 * time.Second
	consentMaxFailedRequests = 5
	maxSessionTokenLength    = 4096
	maxLinkTicketLength      = 256
	maxResponseBodySize      = 1 << 20
)

var (
	errSignInCancelled  = errors.New("sign-in was cancelled in the browser")
	errSignInPending    = errors.New("sign-in is not confirmed yet")
	openBrowser         = startBrowser
	consentPollInterval = 2 * time.Second
)

// consentLogin is one sign-in attempt. The person confirms it in the browser
// and this terminal then collects the session. The state in the link names the
// sign-in; the verifier never leaves this process, so nobody else who sees the
// link can collect the session.
type consentLogin struct {
	authorizeEndpoint string
	authorizeURL      string
	startURL          string
	tokenURL          string
	state             string
	verifier          string
}

func GetTokenFromConsentFlow(cfg *config.ClientConfig, ctx context.Context) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	waitCtx, stopWaiting := context.WithTimeout(ctx, consentLoginTimeout)
	defer stopWaiting()

	login, err := newConsentLogin(cfg.FlotteUrl)
	if err != nil {
		return "", err
	}
	if err := login.requestLink(ctx); err != nil {
		return "", err
	}

	printConsentInstructions(ctx, login, openBrowser(login.authorizeURL))
	stopHotkeys := startBrowserHotkeys(ctx, login.authorizeURL, presentationWriter(ctx), cancel)
	defer stopHotkeys()
	stopSpinner := startAuthorizationWait(presentationWriter(ctx))
	defer stopSpinner()

	return login.waitForSession(waitCtx)
}

func newConsentLogin(serverURL string) (*consentLogin, error) {
	authorizeEndpoint, err := config.JoinEndpoint(serverURL, "/auth/cli/authorize")
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	startURL, err := config.JoinEndpoint(serverURL, "/auth/cli/start")
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
	return &consentLogin{
		authorizeEndpoint: authorizeEndpoint,
		startURL:          startURL,
		tokenURL:          tokenURL,
		state:             state,
		verifier:          verifier,
	}, nil
}

func (l *consentLogin) linkParameters() url.Values {
	sum := sha256.Sum256([]byte(l.verifier))
	query := url.Values{}
	query.Set("client_id", consentClientID)
	query.Set("state", l.state)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	query.Set("code_challenge_method", "S256")
	return query
}

type consentStartResponse struct {
	Ticket string `json:"ticket"`
}

func (l *consentLogin) requestLink(ctx context.Context) error {
	parameters := l.linkParameters()
	status, body, err := postConsentForm(ctx, l.startURL, parameters)
	if err != nil {
		return fmt.Errorf("failed to reach the server to start sign-in: %w", err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGone:
		return errors.New("this Flotte server does not support the sign-in of this CLI - update the Flotte server")
	case http.StatusTooManyRequests:
		return errors.New("the server is handling too many sign-ins - wait a minute and run the command again")
	default:
		return fmt.Errorf("the server refused to start sign-in (HTTP %d)", status)
	}
	var started consentStartResponse
	if err := json.Unmarshal(body, &started); err != nil || !isLinkTicket(started.Ticket) {
		return errors.New("the server sent an invalid answer when starting sign-in")
	}
	parameters.Set("ticket", started.Ticket)
	l.authorizeURL = l.authorizeEndpoint + "?" + parameters.Encode()
	return nil
}

func isLinkTicket(ticket string) bool {
	if ticket == "" || len(ticket) > maxLinkTicketLength {
		return false
	}
	for _, c := range []byte(ticket) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

func postConsentForm(ctx context.Context, endpoint string, form url.Values) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, consentRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: consentRequestTimeout,
		// The request names the sign-in and may carry the verifier; never resend it elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req) //#nosec G107,G704 -- the URL is the configured Flotte server
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

func randomURLToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (l *consentLogin) waitForSession(ctx context.Context) (string, error) {
	interval := consentPollInterval
	failedRequests := 0
	for {
		token, err := l.collect(ctx)
		var unreachable *consentUnreachableError
		switch {
		case err == nil:
			return token, nil
		case errors.Is(err, errSignInPending):
			failedRequests = 0
		case errors.Is(err, errSlowDown):
			interval *= 2
		case errors.As(err, &unreachable) && ctx.Err() == nil:
			failedRequests++
			if failedRequests >= consentMaxFailedRequests {
				return "", err
			}
		case ctx.Err() == nil:
			return "", err
		}

		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return "", fmt.Errorf("sign-in timed out after %s - run the command again", consentLoginTimeout)
			}
			return "", ctx.Err()
		}
	}
}

var errSlowDown = errors.New("the server asked to wait longer between requests")

type consentUnreachableError struct{ cause error }

func (e *consentUnreachableError) Error() string {
	return fmt.Sprintf("failed to reach the server to complete sign-in: %v", e.cause)
}

func (e *consentUnreachableError) Unwrap() error { return e.cause }

type consentTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type consentTokenError struct {
	Error string `json:"error"`
}

func (l *consentLogin) collect(ctx context.Context) (string, error) {
	form := url.Values{}
	form.Set("grant_type", consentGrantType)
	form.Set("client_id", consentClientID)
	form.Set("state", l.state)
	form.Set("code_verifier", l.verifier)

	status, body, err := postConsentForm(ctx, l.tokenURL, form)
	if err != nil {
		return "", &consentUnreachableError{cause: err}
	}

	if status == http.StatusTooManyRequests {
		return "", errSlowDown
	}
	if status != http.StatusOK {
		var tokenErr consentTokenError
		_ = json.Unmarshal(body, &tokenErr)
		switch tokenErr.Error {
		case "authorization_pending":
			return "", errSignInPending
		case "access_denied":
			return "", errSignInCancelled
		case "server_error":
			return "", errors.New("the sign-in failed on the server - run the command again")
		case "invalid_grant":
			return "", errors.New("the server rejected this sign-in - run the command again")
		case "unsupported_grant_type":
			return "", errors.New("this Flotte server does not support the sign-in of this CLI - update the Flotte server")
		}
		return "", fmt.Errorf("the server refused to complete sign-in (HTTP %d)", status)
	}
	var token consentTokenResponse
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

func printConsentInstructions(ctx context.Context, login *consentLogin, launchErr error) {
	out := presentationWriter(ctx)
	if launchErr != nil {
		fmt.Fprintf(out, "Could not open the browser automatically.\nVisit: %s\n", login.authorizeURL)
		printConsentLinkHint(out)
	} else {
		fmt.Fprintln(out, "Browser opened. Confirm the sign-in in your browser.")
		if showLoginURL(ctx) {
			fmt.Fprintf(out, "Visit: %s\n", login.authorizeURL)
			printConsentLinkHint(out)
		} else {
			fmt.Fprintln(out, "Press x to show the login link, or c to copy it.")
			fmt.Fprintln(out, "You can also cancel and rerun setup with --show-login-url.")
		}
	}
}

func printConsentLinkHint(out io.Writer) {
	fmt.Fprintln(out, "You can open the link in a browser on another device. Never send it to another person.")
}
