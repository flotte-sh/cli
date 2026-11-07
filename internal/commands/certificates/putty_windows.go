package certificates

import (
	"fmt"
	"os/user"
	"strings"

	"github.com/flotte-sh/cli/integrations/putty"
	"github.com/flotte-sh/cli/internal/auth"
	common "github.com/flotte-sh/cli/internal/commands/common"
	"github.com/spf13/cobra"
)

func NewPuttyCmd(root *Root) *cobra.Command {
	var executable string
	command := &cobra.Command{
		Use:     "putty [user@]host[:port]",
		Short:   "Open PuTTY with a one-connection Flotte certificate agent",
		Long:    "Open PuTTY with an in-memory Flotte certificate and pinned host key. The Pageant agent closes after delivering the first authentication signature; the terminal stays open. Reconnects require a new command. Without user@, use the current Windows account name. The default port is 22. Stop Pageant or other Flotte desktop launchers first. OpenSSH configuration and saved PuTTY sessions are not used.",
		Example: "flotte putty server.example.com:2222\nflotte putty alice@server.example.com:2222 --putty \"C:\\Program Files\\PuTTY\\putty.exe\"",
		Args:    cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			target := args[0]
			if !strings.Contains(target, "@") {
				account, err := user.Current()
				if err != nil {
					return fmt.Errorf("identify local username; specify user@host:port: %w", err)
				}
				username := account.Username
				if index := strings.LastIndexByte(username, '\\'); index >= 0 {
					username = username[index+1:]
				}
				target = username + "@" + target
			}
			username, address, err := common.ParseSSHTarget(target)
			if err != nil {
				return err
			}
			ctx := auth.WithPresentation(command.Context(), command.OutOrStdout(), true)
			token, err := common.RequireConfigAndAuth(root, ctx, "putty", true)
			if err != nil {
				return err
			}
			return putty.Run(ctx, putty.Options{
				Executable: executable,
				ServerURL:  root.Config.FlotteUrl,
				Token:      token,
				User:       username,
				Address:    address,
				Input:      command.InOrStdin(),
				Output:     command.OutOrStdout(),
				Errors:     command.ErrOrStderr(),
			})
		},
	}
	command.Flags().StringVar(&executable, "putty", "", "Path to putty.exe (otherwise search PATH and standard installation directories)")
	return command
}
