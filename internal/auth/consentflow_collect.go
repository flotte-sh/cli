package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

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

type consentTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type consentTokenError struct {
	Error string `json:"error"`
}

var errSlowDown = errors.New("the server asked to wait longer between requests")

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
