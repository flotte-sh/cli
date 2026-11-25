package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

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

type consentStartResponse struct {
	Ticket string `json:"ticket"`
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
