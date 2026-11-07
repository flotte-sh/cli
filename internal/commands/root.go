package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/flotte-sh/cli/internal/commands/account"
	"github.com/flotte-sh/cli/internal/commands/certificates"
	"github.com/flotte-sh/cli/internal/commands/common"
	"github.com/flotte-sh/cli/internal/commands/start"
	clierrors "github.com/flotte-sh/cli/internal/errors"
	"github.com/spf13/cobra"
)

type Root = common.Root

func init() {
	cobra.EnableCommandSorting = false
}

func NewRoot(version string) *Root {
	r := &Root{}
	r.Command = &cobra.Command{
		Use:           "flotte",
		Short:         "Flotte CLI for SSH certificate and access management",
		Long:          "Flotte manages SSH access with short-lived certificates.\nRun 'flotte <command> --help' for examples.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	r.AddGroup(&cobra.Group{ID: "start", Title: "GET STARTED"})
	r.AddGroup(&cobra.Group{ID: "certificates", Title: "SSH CERTIFICATES"})
	r.AddGroup(&cobra.Group{ID: "account", Title: "ACCOUNT"})

	registerCommands(r, version)

	r.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return clierrors.Wrapf("flag", err, "%s. Run '%s --help' for usage", err.Error(), c.CommandPath())
	})

	return r
}

func registerCommands(r *Root, version string) {
	addCommands(r,
		"start",
		start.NewSetupCmd(r),
		start.NewSSHConfigCmd(),
		start.NewCompletionCmd(r),
	)
	addCommands(r,
		"certificates",
		certificates.NewCertCmd(r),
		certificates.NewSSHCmd(r),
		certificates.NewFileZillaCmd(r),
	)
	addCommands(r,
		"account",
		account.NewConfigCmd(r),
		account.NewLoginCmd(r),
		account.NewLogoutCmd(r),
		account.NewUserCmd(r),
		account.NewVersionCmd(version),
	)
	r.AddCommand(start.NewUninstallCmd())
	registerPlatformCommands(r)

	// These commands are called by OpenSSH and intentionally hidden from help.
	r.AddCommand(certificates.NewSSHHostkeysCmd(r), certificates.NewSSHAgentServeCmd())
}

func addCommands(r *Root, group string, commands ...*cobra.Command) {
	for _, command := range commands {
		command.GroupID = group
		r.AddCommand(command)
	}
}

func Execute(version string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := NewRoot(version).ExecuteContext(ctx); err != nil {
		userMsg := clierrors.GetUserMessage(err)
		fmt.Fprintln(os.Stderr, "Error:", userMsg)

		// Show the underlying cause if it adds information beyond the message
		if cause := clierrors.RootCause(err); cause != "" && cause != userMsg {
			fmt.Fprintln(os.Stderr, "Cause:", cause)
		}

		os.Exit(1)
	}
}
