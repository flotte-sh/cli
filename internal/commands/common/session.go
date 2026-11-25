package common

import (
	"errors"
	"io"

	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/client"
	"github.com/flotte-sh/cli/internal/config"
)

const sessionNotEndedWarning = "The session was removed from this computer but not ended on the server, where it may stay valid until it expires"

var errSessionWithoutServer = errors.New("it was saved by an older CLI that did not record its server")

func EndSession(warnings io.Writer) error {
	var notEnded error
	if session, err := auth.LoadSession(); err == nil {
		notEnded = revokeSession(session)
	}
	if err := auth.DeleteToken(); err != nil {
		return err
	}
	if notEnded != nil {
		auth.PrintWarning(warnings, sessionNotEndedWarning, notEnded)
	}
	return nil
}

func revokeSession(session auth.Session) error {
	if session.Server == "" {
		return errSessionWithoutServer
	}
	return client.RevokeToken(&config.ClientConfig{FlotteUrl: session.Server}, session.Token)
}
