package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/flotte-sh/cli/internal/config"
	clierrors "github.com/flotte-sh/cli/internal/errors"
)

type cliDeviceStartResponse struct {
	DeviceCode      string `json:"deviceCode"`
	UserCode        string `json:"userCode"`
	VerificationURI string `json:"verificationUri"`
	Interval        int64  `json:"interval"`
}

type cliDeviceTokenRequest struct {
	DeviceCode string `json:"deviceCode"`
}

type cliDeviceTokenResponse struct {
	Token    string `json:"token,omitempty"`
	Pending  bool   `json:"pending"`
	SlowDown bool   `json:"slowDown,omitempty"`
}

const deviceCodeWarning = "Enter this code yourself. Whoever enters it signs this machine in as their account, so do not pass it on, and never enter a code that someone else sent you."

var (
	deviceMinPollInterval = 5 * time.Second
	deviceSlowDownStep    = 5 * time.Second
)

func isRateLimited(err error) bool {
	var apiErr *clierrors.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusTooManyRequests
}

func GetTokenFromDeviceFlow(cfg *config.ClientConfig, ctx context.Context) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startURL, err := config.JoinEndpoint(cfg.FlotteUrl, "/auth/cli/device/start")
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}

	startResp, err := postJSONContext[cliDeviceStartResponse](ctx, startURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to start device auth: %w", err)
	}

	fmt.Fprintf(presentationWriter(ctx), "Visit: %s\nCode:  %s\n%s\n", startResp.VerificationURI, startResp.UserCode, deviceCodeWarning)
	stopHotkeys := startAuthorizationHotkeys(ctx, cancel)
	defer stopHotkeys()
	stopWaiting := startAuthorizationWait(presentationWriter(ctx))
	defer stopWaiting()

	interval := max(time.Duration(startResp.Interval)*time.Second, deviceMinPollInterval)

	// Device flows typically expire after 10-15 min on the IdP side.
	// We cap polling at 15 min but also respect the caller's context.
	deadline := time.NewTimer(15 * time.Minute)
	defer deadline.Stop()

	for {
		reqBody, _ := json.Marshal(cliDeviceTokenRequest{DeviceCode: startResp.DeviceCode})
		tokenURL, err := config.JoinEndpoint(cfg.FlotteUrl, "/auth/cli/device/token")
		if err != nil {
			return "", fmt.Errorf("invalid server URL: %w", err)
		}

		resp, err := postJSONContext[cliDeviceTokenResponse](ctx, tokenURL, reqBody)
		switch {
		case isRateLimited(err):
			interval += deviceSlowDownStep
		case err != nil:
			return "", fmt.Errorf("device token exchange failed: %w", err)
		case !resp.Pending:
			return resp.Token, nil
		case resp.SlowDown:
			interval += deviceSlowDownStep
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline.C:
			return "", fmt.Errorf("device auth timed out")
		case <-time.After(interval):
		}
	}
}
