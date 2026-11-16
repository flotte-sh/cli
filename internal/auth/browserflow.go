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
	oauthClientID          = "flotte-cli"
	oauthAuthorizePath     = "/auth/cli/authorize"
	oauthTokenPath         = "/auth/cli/token" // #nosec G101 -- endpoint path, not a credential
	browserLoginTimeout    = 10 * time.Minute
	tokenRequestTimeout    = 30 * time.Second
	loopbackShutdownGrace  = 2 * time.Second
	oauthErrorDisplayLimit = 200
)

var tokenHTTPClient = &http.Client{
	Timeout: tokenRequestTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type browserOpenerKey struct{}

// WithBrowserOpener replaces the system browser launcher for sign-ins started
// with the returned context.
func WithBrowserOpener(ctx context.Context, open func(loginURL string) error) context.Context {
	return context.WithValue(ctx, browserOpenerKey{}, open)
}

func browserOpener(ctx context.Context) func(string) error {
	if open, ok := ctx.Value(browserOpenerKey{}).(func(string) error); ok {
		return open
	}
	return startBrowser
}

type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type oauthErrorResponse struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func GetTokenFromBrowserFlow(cfg *config.ClientConfig, ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, browserLoginTimeout)
	defer cancel()

	issuer, err := config.NormalizeFlotteURL(cfg.FlotteUrl)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	authorizeEndpoint, err := config.JoinEndpoint(issuer, oauthAuthorizePath)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	tokenEndpoint, err := config.JoinEndpoint(issuer, oauthTokenPath)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}

	state, err := randomURLSafe(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate login state: %w", err)
	}
	verifier, err := randomURLSafe(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}

	receiver, err := startLoopbackReceiver(ctx, state, issuer)
	if err != nil {
		return "", fmt.Errorf("failed to listen on the loopback interface for the sign-in response: %w", err)
	}
	defer receiver.close()

	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {oauthClientID},
		"redirect_uri":          {receiver.redirectURI},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	loginURL := authorizeEndpoint + "?" + query.Encode()

	printBrowserInstructions(ctx, loginURL, browserOpener(ctx)(loginURL))
	stopHotkeys := startBrowserHotkeys(ctx, loginURL, presentationWriter(ctx), cancel)
	defer stopHotkeys()
	stopWaiting := startAuthorizationWait(presentationWriter(ctx))
	defer stopWaiting()

	code, err := receiver.wait(ctx)
	if err != nil {
		return "", err
	}

	return redeemAuthorizationCode(ctx, tokenEndpoint, code, receiver.redirectURI, verifier)
}

func redeemAuthorizationCode(ctx context.Context, tokenEndpoint, code, redirectURI, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {oauthClientID},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := tokenHTTPClient.Do(req) //#nosec G107 -- the endpoint is derived from the configured server URL
	if err != nil {
		return "", errors.New("failed to reach the server's token endpoint")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return "", errors.New("failed to read the token response")
	}
	if resp.StatusCode != http.StatusOK {
		var oauthErr oauthErrorResponse
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Code != "" {
			return "", fmt.Errorf("the server rejected the sign-in code: %s", describeOAuthError(oauthErr.Code, oauthErr.Description))
		}
		return "", fmt.Errorf("the server rejected the sign-in code (HTTP %d)", resp.StatusCode)
	}

	var token oauthTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return "", errors.New("the server returned an unreadable token response")
	}
	if !strings.EqualFold(token.TokenType, "Bearer") {
		return "", errors.New("the server returned an unsupported token type")
	}
	if token.AccessToken == "" {
		return "", errors.New("the server returned an empty token")
	}
	return token.AccessToken, nil
}

func randomURLSafe(byteLength int) (string, error) {
	raw := make([]byte, byteLength)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func describeOAuthError(code, description string) string {
	code = printableASCII(code)
	description = printableASCII(description)
	if description == "" {
		return code
	}
	return code + ": " + description
}

func printableASCII(value string) string {
	var cleaned strings.Builder
	for _, char := range value {
		if cleaned.Len() >= oauthErrorDisplayLimit {
			break
		}
		if char >= 0x20 && char <= 0x7e {
			cleaned.WriteRune(char)
		}
	}
	return cleaned.String()
}

func printBrowserInstructions(ctx context.Context, loginURL string, launchErr error) {
	out := presentationWriter(ctx)
	if launchErr != nil {
		fmt.Fprintf(out, "Could not open the browser automatically.\nOpen this link in a browser on this computer:\nVisit: %s\n", loginURL)
		return
	}
	fmt.Fprintln(out, "Browser opened. Complete sign-in in your browser.")
	if showLoginURL(ctx) {
		fmt.Fprintf(out, "Visit: %s\n", loginURL)
	} else {
		fmt.Fprintln(out, "Press x to show the login link, or c to copy it.")
		fmt.Fprintln(out, "You can also cancel and rerun setup with --show-login-url.")
	}
}
