package certificates

import (
	"github.com/flotte-sh/cli/integrations/filezilla"
	"github.com/flotte-sh/cli/internal/auth"
	common "github.com/flotte-sh/cli/internal/commands/common"
	"github.com/spf13/cobra"
)

func NewFileZillaCmd(root *Root) *cobra.Command {
	var executable string
	command := &cobra.Command{
		Use:     "filezilla <user@host[:port]>",
		Short:   "Open FileZilla with a short-lived Flotte certificate",
		Long:    "Open FileZilla with a temporary SFTP profile, Flotte-issued short-lived certificate, and Flotte-approved host keys. Requires FileZilla 3.71.0 or newer; the temporary profile enables 'Allow SSH agent keys of unknown type' and is removed when the command exits.",
		Example: "flotte filezilla alice@server.example.com:2222",
		Args:    cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			user, address, err := common.ParseSSHTarget(args[0])
			if err != nil {
				return err
			}
			site, err := filezilla.NewSite(user, address)
			if err != nil {
				return err
			}
			ctx := auth.WithPresentation(command.Context(), command.OutOrStdout(), true)
			token, err := common.RequireConfigAndAuth(root, ctx, "filezilla", true)
			if err != nil {
				return err
			}
			return filezilla.Run(ctx, filezilla.Options{
				Executable: executable,
				ServerURL:  root.Config.FlotteUrl,
				Token:      token,
				Site:       site,
				Input:      command.InOrStdin(),
				Output:     command.OutOrStdout(),
				Errors:     command.ErrOrStderr(),
			})
		},
	}
	command.Flags().StringVar(&executable, "filezilla", "", "Path to FileZilla (otherwise search PATH and standard installation directories)")
	return command
}
