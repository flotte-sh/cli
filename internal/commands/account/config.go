package account

import (
	"fmt"
	"os"

	"github.com/flotte-sh/flotte-cli/internal/config"
	clierrors "github.com/flotte-sh/flotte-cli/internal/errors"
	"github.com/spf13/cobra"
)

func NewConfigCmd(r *Root) *cobra.Command {
	var (
		flotteURL  string
		showConfig bool
	)

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configure CLI settings",
		Long:  "Configure the Flotte CLI server URL.",
		Args:  cobra.NoArgs,
		Example: "  flotte config --flotte-url https://server.com\n" +
			"  flotte config --show                    # Show current configuration",
		RunE: func(c *cobra.Command, args []string) error {
			const operation = "config"

			cfg, err := config.LoadConfig()
			if err != nil {
				if os.IsNotExist(err) {
					if showConfig {
						fmt.Fprintln(c.OutOrStdout(), "No configuration found. Please run 'flotte setup <server-url>' first.")
						return nil
					}
					cfg = config.NewConfig()
				} else {
					return clierrors.Wrap(operation, err, "failed to load configuration")
				}
			}

			if showConfig {
				fmt.Fprintln(c.OutOrStdout(), "Current configuration:")
				fmt.Fprintf(c.OutOrStdout(), "  Flotte URL:  %s\n", cfg.FlotteUrl)
				return nil
			}

			hasChanges := false

			if flotteURL != "" {
				normalizedURL, err := config.NormalizeFlotteURL(flotteURL)
				if err != nil {
					return clierrors.Wrap(operation, err, "invalid server URL")
				}
				cfg.FlotteUrl = normalizedURL
				hasChanges = true
				fmt.Fprintf(c.OutOrStdout(), "Updated Flotte URL to: %s\n", normalizedURL)
			}

			if !hasChanges {
				fmt.Fprintln(c.OutOrStdout(), "No configuration changes specified. Use --help for usage information.")
				fmt.Fprintln(c.OutOrStdout(), "Use --show to display current configuration.")
				return nil
			}

			if err := cfg.Save(); err != nil {
				return clierrors.Wrap(operation, err, "failed to save configuration")
			}

			fmt.Fprintln(c.OutOrStdout(), "Configuration saved successfully.")
			return nil
		},
	}

	cmd.Flags().StringVar(&flotteURL, "flotte-url", "", "Set the Flotte server URL")
	cmd.Flags().BoolVar(&showConfig, "show", false, "Show current configuration")

	return cmd
}
