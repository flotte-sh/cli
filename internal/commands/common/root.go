package common

import (
	"github.com/flotte-sh/flotte-cli/internal/config"
	clierrors "github.com/flotte-sh/flotte-cli/internal/errors"
	"github.com/spf13/cobra"
)

type Root struct {
	*cobra.Command
	Config *config.ClientConfig
	Token  string
}

func (r *Root) ClientConfig() (*config.ClientConfig, error) {
	if r.Config == nil {
		return nil, config.ErrConfigNotFound
	}
	return r.Config, nil
}

func (r *Root) InitSettings() error {
	const operation = "root.initSettings"

	cfg, err := config.LoadOrCreate()
	if err != nil {
		if err == config.ErrConfigNotFound {
			return clierrors.New(operation, err, "no configuration found - please run 'flotte setup <server-url>' first")
		}
		return clierrors.Wrap(operation, err, "failed to load configuration")
	}

	r.Config = cfg
	return nil
}
