package certificates

import (
	"fmt"

	"github.com/flotte-sh/cli/integrations/openssh"
	common "github.com/flotte-sh/cli/internal/commands/common"
	"github.com/spf13/cobra"
)

func NewSSHHostkeysCmd(root *Root) *cobra.Command {
	return &cobra.Command{
		Use: "ssh-hostkeys reason host user key-type key connection-hash", Hidden: true,
		RunE: func(command *cobra.Command, args []string) error {
			if err := openssh.Hostkeys(command.Context(), command.OutOrStdout(), command.ErrOrStderr(), args, common.OpenSSHSession(root)); err != nil {
				fmt.Fprintln(command.ErrOrStderr(), "Flotte error: "+err.Error())
			}
			return nil
		},
	}
}
