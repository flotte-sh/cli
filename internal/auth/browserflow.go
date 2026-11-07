package auth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/flotte-sh/cli/internal/config"
)

type cliBrowserStartResponse struct {
	AuthURL string `json:"authUrl"`
	FlowID  string `json:"flowId"`
	Secret  string `json:"secret"` // possession secret – required when polling /token
}

type cliBrowserTokenResponse struct {
	Token string `json:"token,omitempty"`
}

func GetTokenFromBrowserFlow(cfg *config.ClientConfig, ctx context.Context) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startURL, err := config.JoinEndpoint(cfg.FlotteUrl, "/auth/cli/browser/start")
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}

	startResp, err := postJSONContext[cliBrowserStartResponse](ctx, startURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to start browser auth: %w", err)
	}

	printBrowserInstructions(ctx, startResp.AuthURL, startBrowser(startResp.AuthURL))
	stopHotkeys := startBrowserHotkeys(ctx, startResp.AuthURL, presentationWriter(ctx), cancel)
	defer stopHotkeys()
	stopWaiting := startAuthorizationWait(presentationWriter(ctx))
	defer stopWaiting()

	reqBody, _ := json.Marshal(map[string]string{
		"flowId": startResp.FlowID,
		"secret": startResp.Secret,
	})
	startResp.Secret = ""
	tokenURL, err := config.JoinEndpoint(cfg.FlotteUrl, "/auth/cli/browser/token")
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}

	resp, err := postJSONContext[cliBrowserTokenResponse](ctx, tokenURL, reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	return resp.Token, nil
}

func printBrowserInstructions(ctx context.Context, loginURL string, launchErr error) {
	out := presentationWriter(ctx)
	if launchErr != nil {
		fmt.Fprintf(out, "Could not open the browser automatically.\nVisit: %s\n", loginURL)
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
