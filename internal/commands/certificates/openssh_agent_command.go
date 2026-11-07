package certificates

import (
	"github.com/flotte-sh/cli/integrations/openssh"
	"github.com/spf13/cobra"
)

func NewSSHAgentServeCmd() *cobra.Command {
	return &cobra.Command{
		Use: "ssh-agent-serve connection-hash", Hidden: true, DisableFlagParsing: true,
		Run: func(command *cobra.Command, args []string) {
			if len(args) != 1 {
				return
			}
			_ = openssh.Serve(command.Context(), command.InOrStdin(), command.OutOrStdout(), args[0])
		},
	}
}
