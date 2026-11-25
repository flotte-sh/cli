package account

import (
	"fmt"

	common "github.com/flotte-sh/cli/internal/commands/common"
	clierrors "github.com/flotte-sh/cli/internal/errors"
	"github.com/spf13/cobra"
)

func NewLogoutCmd(_ *Root) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Logout and delete cached authentication token",
		Long:  "Revoke the server-side session and remove the cached authentication token, requiring re-authentication on the next command that needs API access.",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			const operation = "logout"

			if err := common.EndSession(c.ErrOrStderr()); err != nil {
				return clierrors.Wrap(operation, err, "failed to delete cached token")
			}
			fmt.Fprintln(c.OutOrStdout(), "Successfully logged out.")
			return nil
		},
	}
}
