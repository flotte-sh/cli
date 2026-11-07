package start

import (
	"fmt"

	"github.com/flotte-sh/cli/integrations/openssh"
	"github.com/spf13/cobra"
)

func NewSSHConfigCmd() *cobra.Command {
	setupCmd := &cobra.Command{
		Use:   "ssh-config",
		Short: "Manage native OpenSSH integration",
		Long:  "Add or remove the Flotte-managed KnownHostsCommand and IdentityAgent block in ~/.ssh/config. Other SSH settings are preserved.",
	}

	setupCmd.AddCommand(&cobra.Command{
		Use:     "install",
		Aliases: []string{"enable"},
		Short:   "Enable Flotte certificates for ssh, scp, and sftp",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			status, err := openssh.InstallConfig()
			if err != nil {
				return err
			}
			switch status {
			case openssh.InstallStatusUpdated:
				fmt.Fprintln(c.OutOrStdout(), "SSH configuration updated successfully.")
			case openssh.InstallStatusUnchanged:
				fmt.Fprintln(c.OutOrStdout(), "SSH is already configured for flotte.")
			default:
				fmt.Fprintln(c.OutOrStdout(), "SSH configuration installed successfully.")
			}
			return nil
		},
	})

	setupCmd.AddCommand(&cobra.Command{
		Use:     "uninstall",
		Aliases: []string{"disable"},
		Short:   "Remove the Flotte-managed OpenSSH configuration",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if err := openssh.UninstallConfig(); err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), "SSH configuration removed successfully.")
			return nil
		},
	})

	return setupCmd
}
