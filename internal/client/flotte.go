package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/flotte-sh/flotte-cli/internal/config"
	clierrors "github.com/flotte-sh/flotte-cli/internal/errors"
)

type SshCertRequest struct {
	ServerHostkey   string `json:"serverHostkey"`
	ServerUser      string `json:"user"`
	PublicKeyString string `json:"publicKey"`
}

type SshCertResponse struct {
	Certificate string   `json:"certificate"`
	Hostkeys    []string `json:"hostkeys"`
	Warning     string   `json:"warning,omitempty"`
}

type UserInfoResponse struct {
	Authenticated bool     `json:"authenticated"`
	Subject       string   `json:"sub,omitempty"`
	Email         string   `json:"email,omitempty"`
	Name          string   `json:"name,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

func RequestCertificate(ctx context.Context, cfg *config.ClientConfig, token string, userPublicKey, serverHostkey, serverUserName string) (*SshCertResponse, error) {
	const operation = "client.RequestCertificate"

	if token == "" {
		return nil, clierrors.New(operation, nil, "no authentication token - please run 'flotte login'")
	}

	cli := &http.Client{Timeout: 60 * time.Second}

	requestBody := &SshCertRequest{
		ServerHostkey:   serverHostkey,
		PublicKeyString: userPublicKey,
		ServerUser:      serverUserName,
	}

	out, err := json.Marshal(requestBody)
	if err != nil {
		return nil, clierrors.Wrap(operation, err, "failed to prepare certificate request")
	}

	endpoint, err := config.JoinEndpoint(cfg.FlotteUrl, "/ssh/cert")
	if err != nil {
		return nil, clierrors.Wrap(operation, err, "invalid server URL")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(out))
	if err != nil {
		return nil, clierrors.Wrap(operation, err, "failed to create request")
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-flotte-token", token)

	resp, err := cli.Do(req) //#nosec G704 -- FlotteUrl is user-configured CLI setting, not attacker-controlled input
	if err != nil {
		return nil, clierrors.Wrap(operation, err, "failed to connect to server - check your network connection")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, clierrors.ParseApiError(resp)
	}

	var certResp SshCertResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return nil, clierrors.Wrap(operation, err, "failed to parse server response")
	}

	return &certResp, nil
}

func RevokeToken(cfg *config.ClientConfig, token string) error {
	const operation = "client.RevokeToken"

	endpoint, err := config.JoinEndpoint(cfg.FlotteUrl, "/auth/logout")
	if err != nil {
		return clierrors.Wrap(operation, err, "invalid server URL")
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return clierrors.Wrap(operation, err, "failed to create logout request")
	}
	req.Header.Set("X-flotte-token", token)

	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Do(req) //#nosec G107 -- FlotteUrl is user-configured CLI setting, not attacker-controlled input
	if err != nil {
		return clierrors.Wrap(operation, err, "failed to connect to server")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return clierrors.ParseApiError(resp)
	}
	return nil
}

func FetchUserInfo(ctx context.Context, cfg *config.ClientConfig, token string) (*UserInfoResponse, error) {
	const operation = "client.FetchUserInfo"

	endpoint, err := config.JoinEndpoint(cfg.FlotteUrl, "/auth/me")
	if err != nil {
		return nil, clierrors.Wrap(operation, err, "invalid server URL")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, clierrors.Wrap(operation, err, "failed to create request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-flotte-token", token)

	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, clierrors.Wrap(operation, err, "failed to connect to server - check your network connection")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return &UserInfoResponse{Authenticated: false}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, clierrors.ParseApiError(resp)
	}

	var ui UserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&ui); err != nil {
		return nil, clierrors.Wrap(operation, err, "failed to parse server response")
	}
	return &ui, nil
}
