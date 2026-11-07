package start

import (
	"errors"
	"fmt"

	"github.com/flotte-sh/cli/integrations/openssh"
	"github.com/spf13/cobra"
)

func NewUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "uninstall",
		Short:   "Remove all shell completions and SSH integration",
		Long:    "Remove Flotte's managed shell completion files and automatic SSH integration. Keeps the CLI binary, account configuration, and SSH keys.",
		GroupID: "start",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var failures []error
			for _, shell := range supportedShells {
				if _, _, err := removeCompletion(shell); err != nil {
					failures = append(failures, fmt.Errorf("remove %s completion: %w", shell, err))
				}
			}
			if err := openssh.RemoveConfigIfPresent(); err != nil {
				failures = append(failures, err)
			}
			if err := errors.Join(failures...); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Shell completions and SSH integration removed. Restart your shell to unload completion.")
			return nil
		},
	}
}
