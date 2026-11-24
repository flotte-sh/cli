package start

import (
	"errors"
	"fmt"

	"github.com/flotte-sh/cli/integrations/openssh"
	common "github.com/flotte-sh/cli/internal/commands/common"
	"github.com/spf13/cobra"
)

func NewUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "uninstall",
		Short:   "Remove shell completions, SSH integration, and the cached session",
		Long:    "Remove Flotte's managed shell completion files, automatic SSH integration, and cached sign-in session. The session is also revoked on the server when it is reachable. Keeps the CLI binary, account configuration, and SSH keys.",
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
			if err := common.EndSession(); err != nil {
				failures = append(failures, fmt.Errorf("remove session: %w", err))
			}
			if err := errors.Join(failures...); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Shell completions, SSH integration, and session removed. Restart your shell to unload completion.")
			return nil
		},
	}
}
