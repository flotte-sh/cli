package auth

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/flotte-sh/cli/internal/client"
	"github.com/flotte-sh/cli/internal/config"
	clierrors "github.com/flotte-sh/cli/internal/errors"
)

type (
	showLoginURLKey       struct{}
	presentationWriterKey struct{}
)

func WithPresentation(ctx context.Context, out io.Writer, showURL bool) context.Context {
	return context.WithValue(WithShowLoginURL(ctx, showURL), presentationWriterKey{}, out)
}

func presentationWriter(ctx context.Context) io.Writer {
	if out, ok := ctx.Value(presentationWriterKey{}).(io.Writer); ok {
		return out
	}
	return os.Stdout
}

func WithShowLoginURL(ctx context.Context, show bool) context.Context {
	return context.WithValue(ctx, showLoginURLKey{}, show)
}

func showLoginURL(ctx context.Context) bool {
	show, ok := ctx.Value(showLoginURLKey{}).(bool)
	return !ok || show
}

var (
	browserToken = GetTokenFromBrowserFlow
	deviceToken  = GetTokenFromDeviceFlow
)

func InitAuth(cfg *config.ClientConfig, ctx context.Context, allowInteractive bool) (string, error) {
	const operation = "initAuth"

	if token, err := LoadToken(); err == nil {
		userInfo, err := client.FetchUserInfo(ctx, cfg, token)
		if err != nil {
			return "", clierrors.Wrap(operation, err, "failed to validate cached session")
		}
		if userInfo.Authenticated {
			return token, nil
		}
		if err := DeleteToken(); err != nil {
			return "", clierrors.Wrap(operation, err, "failed to remove invalid cached session")
		}
	}

	if !allowInteractive {
		return "", clierrors.New(operation, nil, "no valid cached token available and interactive auth is disabled - run 'flotte login' once, then retry the command")
	}

	authMode, discoveryErr := discoverMethod(ctx, cfg.FlotteUrl)
	if discoveryErr != nil {
		return "", clierrors.Wrap(operation, discoveryErr, "failed to discover server authentication methods")
	}

	var (
		token  string
		err    error
		method string
	)
	switch authMode {
	case authMethodBrowser:
		method = authMethodBrowser
		token, err = browserToken(cfg, ctx)
	case authMethodDevice:
		method = "device flow"
		token, err = deviceToken(cfg, ctx)
	default:
		return "", clierrors.Newf(operation, nil, "unsupported server authentication method %q", authMode)
	}
	if err != nil {
		return "", clierrors.Wrap(operation, err, fmt.Sprintf("%s authentication failed. Retry with 'flotte login'.", method))
	}

	if err := SaveToken(token); err != nil {
		return "", clierrors.Wrap(operation, err, "authentication succeeded but the CLI could not save the token - run 'flotte login' again")
	}

	userInfo, err := client.FetchUserInfo(ctx, cfg, token)
	if err != nil {
		return "", clierrors.Wrap(operation, err, "authentication succeeded but session validation failed")
	}
	if !userInfo.Authenticated {
		if err := DeleteToken(); err != nil {
			return "", clierrors.Wrap(operation, err, "authentication created an invalid session that could not be removed")
		}
		return "", clierrors.New(operation, nil, "authentication did not create a valid session - retry with 'flotte login'")
	}

	return token, nil
}
