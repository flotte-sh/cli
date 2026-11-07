package openssh

import (
	"context"

	"github.com/flotte-sh/cli/internal/client"
)

type Session struct {
	Authenticate       func(ctx context.Context, operation string, allowInteractive bool) (string, error)
	RequestCertificate func(ctx context.Context, token, publicKey, hostKey, loginUser string) (*client.SshCertResponse, error)
	RequireSSHKey      func(operation string) (string, error)
}
