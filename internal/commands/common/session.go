package common

import (
	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/client"
	"github.com/flotte-sh/cli/internal/config"
)

func EndSession() error {
	if cfg, err := config.LoadOrCreate(); err == nil {
		if token, err := auth.LoadToken(); err == nil && token != "" {
			_ = client.RevokeToken(cfg, token)
		}
	}
	return auth.DeleteToken()
}
