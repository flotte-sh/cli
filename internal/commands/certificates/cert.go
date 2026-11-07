package certificates

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/flotte-sh/cli/internal/client"
	common "github.com/flotte-sh/cli/internal/commands/common"
	clierrors "github.com/flotte-sh/cli/internal/errors"
	"github.com/flotte-sh/cli/internal/sshhelper"
	"github.com/spf13/cobra"
)

func NewCertCmd(root *Root) *cobra.Command {
	certCmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage SSH certificates",
		Long:  "Request and inspect SSH user certificates issued by the Flotte CA.",
	}

	certCmd.AddCommand(&cobra.Command{
		Use:   "get <user@server[:port]> <public-key-or-path>",
		Short: "Request a new SSH certificate",
		Long:  "Request a certificate for a server and user. Username is REQUIRED. Specify the server with optional port using the format: user@server[:port] (defaults to port 22 if not specified). The public key can be either a raw key string or a path to a public key file.",
		Example: `flotte cert get root@myserver.example.com:22 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC3..."
flotte cert get root@myserver.example.com:22 ~/.ssh/id_ed25519.pub`,
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			const operation = "cert.get"

			token, err := common.RequireConfigAndAuth(root, c.Context(), operation, true)
			if err != nil {
				return err
			}

			target := args[0]
			serverUser, serverAddress, err := common.ParseSSHTarget(target)
			if err != nil {
				return err
			}

			pubKey, err := common.ResolvePublicKey(args[1])
			if err != nil {
				return err
			}

			hostkey, err := sshhelper.QueryServerHostkey(serverAddress)
			if err != nil {
				return clierrors.Wrapf(operation, err, "failed to get server hostkey for %s", serverAddress)
			}

			result, err := client.RequestCertificate(c.Context(), root.Config, token, pubKey, hostkey, serverUser)
			if err != nil {
				return clierrors.Wrap(operation, err, clierrors.GetUserMessage(err))
			}

			fmt.Fprintln(c.OutOrStdout(), result.Certificate)
			return nil
		},
	})

	certCmd.AddCommand(&cobra.Command{
		Use:   "inspect <user@server[:port]>",
		Short: "Download and inspect a certificate with ssh-keygen",
		Long:  "Request a certificate for the given target and run `ssh-keygen -L -f` on the downloaded cert, printing the result to stdout.",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			const operation = "cert.inspect"

			token, err := common.RequireConfigAndAuth(root, c.Context(), operation, true)
			if err != nil {
				return err
			}

			target := args[0]
			serverUser, serverAddress, err := common.ParseSSHTarget(target)
			if err != nil {
				return err
			}

			pubKey, err := common.RequireSSHKey(operation)
			if err != nil {
				return err
			}

			fmt.Fprintf(c.OutOrStdout(), "Resolving hostkey for %s...\n", serverAddress)
			hostkey, err := sshhelper.QueryServerHostkey(serverAddress)
			if err != nil {
				return clierrors.Wrapf(operation, err, "failed to get server hostkey for %s", serverAddress)
			}
			fmt.Fprintf(c.OutOrStdout(), "Got hostkey: %s\n\n", hostkey)

			certResp, err := client.RequestCertificate(c.Context(), root.Config, token, pubKey, hostkey, serverUser)
			if err != nil {
				return clierrors.Wrap(operation, err, clierrors.GetUserMessage(err))
			}

			tmpFile, err := os.CreateTemp("", "flotte-cert-*.pub")
			if err != nil {
				return clierrors.Wrap(operation, err, "failed to create temporary file")
			}
			tmpPath := tmpFile.Name()
			defer func() {
				_ = tmpFile.Close()
				_ = os.Remove(tmpPath)
			}()

			if _, err := tmpFile.WriteString(certResp.Certificate); err != nil {
				return clierrors.Wrap(operation, err, "failed to write certificate to file")
			}
			if err := tmpFile.Close(); err != nil {
				return clierrors.Wrap(operation, err, "failed to close certificate file")
			}

			cmd := exec.CommandContext(c.Context(), "ssh-keygen", "-L", "-f", tmpPath) //#nosec G204,G702
			cmd.Stderr = c.OutOrStderr()
			out, err := cmd.Output()
			if err != nil {
				return clierrors.Wrap(operation, err, "ssh-keygen failed - make sure ssh-keygen is installed")
			}

			_, _ = c.OutOrStdout().Write(out)

			return nil
		},
	})

	return certCmd
}
