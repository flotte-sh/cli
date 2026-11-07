package certificates

import (
	"github.com/flotte-sh/cli/integrations/winscp"
	"github.com/flotte-sh/cli/internal/auth"
	common "github.com/flotte-sh/cli/internal/commands/common"
	"github.com/spf13/cobra"
)

func NewWinSCPCmd(root *Root) *cobra.Command {
	var executable string
	command := &cobra.Command{
		Use:     "winscp <user@host[:port]>",
		Short:   "Open WinSCP with a short-lived Flotte certificate",
		Long:    "Open WinSCP using a fresh in-memory key and a target-scoped Pageant agent. Certificates are requested only when a client needs an identity and the cached certificate has expired. Keep this command and WinSCP running for background transfers and Open in PuTTY. The Pageant named pipe must be free; an existing pipe owner is never replaced. OpenSSH aliases and jump-host settings are not used.",
		Example: "flotte winscp alice@server.example.com\nflotte winscp alice@server.example.com:2222 --winscp \"C:\\Program Files (x86)\\WinSCP\\WinSCP.exe\"",
		Args:    cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			user, address, err := common.ParseSSHTarget(args[0])
			if err != nil {
				return err
			}
			ctx := auth.WithPresentation(command.Context(), command.OutOrStdout(), true)
			token, err := common.RequireConfigAndAuth(root, ctx, "winscp", true)
			if err != nil {
				return err
			}
			return winscp.Run(ctx, winscp.Options{
				Executable: executable,
				ServerURL:  root.Config.FlotteUrl,
				Token:      token,
				User:       user,
				Address:    address,
				Input:      command.InOrStdin(),
				Output:     command.OutOrStdout(),
				Errors:     command.ErrOrStderr(),
			})
		},
	}
	command.Flags().StringVar(&executable, "winscp", "", "Path to WinSCP.exe (otherwise search PATH and standard installation directories)")
	return command
}
