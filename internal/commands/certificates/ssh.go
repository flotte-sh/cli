package certificates

import (
	"github.com/flotte-sh/cli/integrations/openssh"
	"github.com/flotte-sh/cli/internal/commands/common"
	"github.com/spf13/cobra"
)

func NewSSHCmd(root *Root) *cobra.Command {
	return &cobra.Command{
		Use:   "ssh [--legacy] [ssh-options...] [user@]hostname [command...]",
		Short: "Connect using OpenSSH and an on-demand Flotte certificate",
		Long:  "Run OpenSSH with Flotte's host-key verification and certificate agent for this connection. All OpenSSH options are passed through unchanged.\n\nUse --legacy to request a certificate before launching OpenSSH with explicit identity, certificate, and known-hosts files.",
		Example: `  flotte ssh user@host
  flotte ssh -p 2222 user@host
  flotte ssh -L 8080:localhost:80 user@host
  flotte ssh --legacy user@host`,
		DisableFlagParsing: true,
		Args:               cobra.MinimumNArgs(1),
		ValidArgsFunction:  completeSSHOptions,
		RunE: func(command *cobra.Command, args []string) error {
			if isSSHHelpRequest(args) {
				return command.Help()
			}
			return openssh.Run(command.Context(), command.OutOrStdout(), command.ErrOrStderr(), args, common.OpenSSHSession(root))
		},
	}
}

func isSSHHelpRequest(args []string) bool {
	return len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help")
}

func completeSSHOptions(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return []string{
		"-4\tUse IPv4 addresses only",
		"-6\tUse IPv6 addresses only",
		"-l\tSpecify the login user",
		"-p\tSpecify the destination port",
		"-i\tSelect an identity file",
		"-L\tForward a local port",
		"-R\tForward a remote port",
		"-D\tOpen a SOCKS proxy",
	}, cobra.ShellCompDirectiveNoFileComp
}
