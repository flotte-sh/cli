package common

import (
	"context"

	"github.com/flotte-sh/cli/integrations/openssh"
	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/client"
	"github.com/flotte-sh/cli/internal/config"
	clierrors "github.com/flotte-sh/cli/internal/errors"
)

func RequireConfigAndAuth(root *Root, ctx context.Context, operation string, allowInteractive bool) (string, error) {
	if root.Config == nil {
		if err := root.InitSettings(); err != nil {
			return "", clierrors.Wrap(operation, err, clierrors.GetUserMessage(err))
		}
	}
	token, err := auth.InitAuth(root.Config, ctx, allowInteractive)
	if err != nil {
		return "", clierrors.Wrap(operation, err, clierrors.GetUserMessage(err))
	}
	return token, nil
}

func RequireSSHKey(operation string) (string, error) {
	pubKey, err := config.GetActiveSSHPublicKey()
	if err != nil {
		return "", clierrors.Wrap(operation, err, "failed to get SSH public key")
	}
	return pubKey, nil
}

func OpenSSHSession(root *Root) openssh.Session {
	return openssh.Session{
		Authenticate: func(ctx context.Context, operation string, allowInteractive bool) (string, error) {
			return RequireConfigAndAuth(root, ctx, operation, allowInteractive)
		},
		RequestCertificate: func(ctx context.Context, token, publicKey, hostKey, loginUser string) (*client.SshCertResponse, error) {
			return client.RequestCertificate(ctx, root.Config, token, publicKey, hostKey, loginUser)
		},
		RequireSSHKey: RequireSSHKey,
	}
}
