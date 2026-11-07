package account

import (
	"fmt"

	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/client"
	common "github.com/flotte-sh/cli/internal/commands/common"
	clierrors "github.com/flotte-sh/cli/internal/errors"
	"github.com/spf13/cobra"
)

func NewLoginCmd(r *Root) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Login to your flotte instance",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			const operation = "login"

			token, err := common.RequireConfigAndAuth(r, c.Context(), operation, true)
			if err != nil {
				return err
			}

			cfg, _ := r.ClientConfig()
			if cfg != nil {
				ui, err := client.FetchUserInfo(c.Context(), cfg, token)
				if err != nil {
					return clierrors.Wrap(operation, err, "failed to fetch authenticated user")
				}
				if !ui.Authenticated {
					if err := auth.DeleteToken(); err != nil {
						return clierrors.Wrap(operation, err, "session expired during login and could not be removed")
					}
					return clierrors.New(operation, nil, "session expired during login - retry with 'flotte login'")
				}
				identifier := ui.Email
				if identifier == "" {
					identifier = ui.Name
				}
				if identifier == "" {
					identifier = ui.Subject
				}
				if identifier != "" {
					fmt.Fprintf(c.OutOrStdout(), "Logged in as %s\n", identifier)
				}
			}

			fmt.Fprintln(c.OutOrStdout(), "Successfully authenticated.")
			return nil
		},
	}
}

func NewLogoutCmd(r *Root) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Logout and delete cached authentication token",
		Long:  "Revoke the server-side session and remove the cached authentication token, requiring re-authentication on the next command that needs API access.",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			const operation = "logout"

			if cfg, _ := r.ClientConfig(); cfg != nil {
				if token, err := auth.LoadToken(); err == nil && token != "" {
					_ = client.RevokeToken(cfg, token)
				}
			}

			if err := auth.DeleteToken(); err != nil {
				return clierrors.Wrap(operation, err, "failed to delete cached token")
			}
			fmt.Fprintln(c.OutOrStdout(), "Successfully logged out.")
			return nil
		},
	}
}

func NewUserCmd(r *Root) *cobra.Command {
	return &cobra.Command{
		Use:     "user",
		Aliases: []string{"whoami"},
		Short:   "Show the current logged-in user",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			const operation = "user"

			token, err := common.RequireConfigAndAuth(r, c.Context(), operation, true)
			if err != nil {
				return err
			}

			cfg, err := r.ClientConfig()
			if err != nil {
				return clierrors.Wrap(operation, err, "failed to load configuration")
			}

			ui, err := client.FetchUserInfo(c.Context(), cfg, token)
			if err != nil {
				return clierrors.Wrap(operation, err, "failed to fetch user information")
			}
			if !ui.Authenticated {
				return clierrors.New(operation, nil, "not authenticated - run 'flotte login' first")
			}

			identifier := ui.Email
			if identifier == "" {
				identifier = ui.Name
			}
			if identifier == "" {
				identifier = ui.Subject
			}
			if identifier == "" {
				identifier = "unknown"
			}
			fmt.Fprintf(c.OutOrStdout(), "%s (server: %s)\n", identifier, cfg.FlotteUrl)
			return nil
		},
	}
}
