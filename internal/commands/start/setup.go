package start

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/flotte-sh/cli/integrations/openssh"
	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/client"
	"github.com/flotte-sh/cli/internal/config"
	clierrors "github.com/flotte-sh/cli/internal/errors"
	"github.com/spf13/cobra"
)

type setupOptions struct {
	showURL           bool
	nonInteractive    bool
	installSSHConfig  bool
	installCompletion bool
}

var errSetupURLNotConfigured = errors.New("no server URL provided and no saved Flotte URL")

func resolveSetupURL(args []string, savedURL string) (string, error) {
	serverURL := savedURL
	if len(args) > 0 {
		serverURL = args[0]
	} else if serverURL == "" {
		return "", errSetupURLNotConfigured
	}

	normalizedURL, err := config.NormalizeFlotteURL(serverURL)
	if err != nil {
		return "", err
	}
	return normalizedURL, nil
}

func NewSetupCmd(r *Root) *cobra.Command {
	var options setupOptions
	cmd := &cobra.Command{
		Use:   "setup [flotte-url]",
		Short: "Connect the CLI to a Flotte server",
		Long:  "Discover the server configuration, sign in, and optionally enable native SSH integration and shell completion. Reuse the saved server URL when the argument is omitted.",
		Example: `  flotte setup https://flotte.example.com
  flotte setup https://flotte.example.com --non-interactive
  flotte setup https://flotte.example.com --non-interactive --install-ssh-config --install-completion
  flotte setup`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			const operation = "setup"

			cfg, err := config.LoadConfig()
			if err != nil {
				if os.IsNotExist(err) {
					cfg = config.NewConfig()
				} else {
					return clierrors.Wrap(operation, err, "failed to load existing configuration")
				}
			}

			flotteURL, err := resolveSetupURL(args, cfg.FlotteUrl)
			if errors.Is(err, errSetupURLNotConfigured) {
				return clierrors.New(operation, err, "no Flotte URL configured - please run 'flotte setup <server-url>' first")
			}
			if err != nil {
				return clierrors.Wrap(operation, err, "invalid server URL")
			}

			discoveryURL := flotteURL
			setupConfig, err := auth.Discover(c.Context(), flotteURL)
			if err != nil {
				return clierrors.Wrap(operation, err, "failed to discover server configuration")
			}

			if setupConfig.BaseURL != "" {
				flotteURL, err = config.NormalizeFlotteURL(setupConfig.BaseURL)
				if err != nil {
					return clierrors.Wrap(operation, err, "server returned an invalid base URL")
				}
			}
			cfg.FlotteUrl = flotteURL

			if err := cfg.Save(); err != nil {
				return clierrors.Wrap(operation, err, "failed to save configuration")
			}

			timeline := newSetupTimeline(c.OutOrStdout())

			if err := r.InitSettings(); err != nil {
				return clierrors.Wrap(operation, err, "failed to load settings - you can retry by running 'flotte login'")
			}

			_, noColor := os.LookupEnv("NO_COLOR")
			_, interactive := setupCapabilities(isSetupTerminal(c.OutOrStdout()), isSetupTerminal(c.InOrStdin()), os.Getenv("TERM"), noColor, runtime.GOOS)
			ctx := auth.WithDiscovery(c.Context(), discoveryURL, setupConfig)
			token, err := auth.InitAuth(r.Config, auth.WithPresentation(ctx, c.OutOrStdout(), options.showURL || !interactive), true)
			if err != nil {
				return clierrors.Wrap(operation, err, fmt.Sprintf("%s You can also retry later with 'flotte login'.", clierrors.GetUserMessage(err)))
			}
			userInfo, err := client.FetchUserInfo(c.Context(), r.Config, token)
			if err != nil {
				return clierrors.Wrap(operation, err, "failed to fetch authenticated user")
			}
			email := userInfo.Email
			if email == "" {
				email = userInfo.Name
			}
			fmt.Fprintf(c.OutOrStdout(), "\n%s\n  Server  %s\n  Email   %s\n", timeline.accent("Config"), flotteURL, maskSetupEmail(email))

			certificates, next, err := configureSetupSSH(c, options, interactive)
			if err != nil {
				return err
			}
			completion, err := configureSetupCompletion(c, r, options, interactive)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "\n%s\n  Sign-in   complete\n  SSH       %s\n  Completion %s\n  Next      %s\n", timeline.accent("Setup complete"), certificates, completion, next)

			return nil
		},
	}
	cmd.Flags().BoolVar(&options.showURL, "show-login-url", false, "Show the browser sign-in URL even when the browser opens successfully")
	cmd.Flags().BoolVar(&options.nonInteractive, "non-interactive", false, "Run setup without prompts")
	cmd.Flags().BoolVar(&options.installSSHConfig, "install-ssh-config", false, "Install SSH integration so you can use ssh directly instead of flotte ssh")
	cmd.Flags().BoolVar(&options.installCompletion, "install-completion", false, "Install shell completion without prompting")
	cmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	return cmd
}

func configureSetupSSH(cmd *cobra.Command, options setupOptions, interactive bool) (string, string, error) {
	configured, err := openssh.IsConfigured()
	if err != nil {
		return "", "", clierrors.Wrap("setup", err, "failed to read SSH configuration")
	}
	if configured {
		return "SSH config already enabled", "Just use SSH as usual: ssh user@host", nil
	}
	install := options.installSSHConfig
	if !install && !options.nonInteractive {
		install, err = chooseCertificateMode(cmd.Context(), cmd.OutOrStdout(), cmd.InOrStdin(), interactive)
	}
	if err != nil {
		return "", "", clierrors.Wrap("setup", err, "SSH access setup cancelled")
	}
	if !install {
		return "SSH config not enabled", "Connect through Flotte: flotte ssh user@host", nil
	}
	if _, err := openssh.InstallConfig(); err != nil {
		return "", "", clierrors.Wrap("setup", err, "failed to configure SSH - you can retry by running 'flotte ssh-config install'")
	}
	return "SSH config enabled", "Just use SSH as usual: ssh user@host", nil
}

func configureSetupCompletion(cmd *cobra.Command, root *Root, options setupOptions, interactive bool) (string, error) {
	shell := detectedShell(runtime.GOOS, os.Getenv("SHELL"))
	if isCompletionInstalled(shell) {
		return fmt.Sprintf("already installed for %s", shell), nil
	}
	install := options.installCompletion
	var err error
	if !install && interactive && !options.nonInteractive {
		install, err = chooseCompletionInstallation(cmd.Context(), cmd.OutOrStdout(), cmd.InOrStdin(), shell)
	}
	if err != nil {
		return "", clierrors.Wrap("setup", err, "shell completion setup cancelled")
	}
	if !install {
		return "not installed", nil
	}
	if _, err := installCompletion(root, shell); err != nil {
		return "", clierrors.Wrap("setup", err, "failed to install shell completion")
	}
	return fmt.Sprintf("installed for %s", shell), nil
}

func maskSetupEmail(email string) string {
	separator := strings.LastIndexByte(email, '@')
	if separator <= 0 || separator == len(email)-1 {
		return maskSetupEmailPart(email)
	}
	return maskSetupEmailPart(email[:separator]) + email[separator:]
}

func maskSetupEmailPart(part string) string {
	if len(part) < 3 {
		return strings.Repeat("*", len(part))
	}
	return part[:2] + strings.Repeat("*", len(part)-3) + part[len(part)-1:]
}

func chooseCertificateMode(ctx context.Context, out io.Writer, in io.Reader, interactive bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if interactive {
		choice := "setup"
		fmt.Fprintln(out)
		form := huh.NewSelect[string]().Title("Configure SSH to automatically use Flotte").Options(
			huh.NewOption("YES  Configure SSH to automatically use Flotte\n     Then use: ssh user@host", "setup"),
			huh.NewOption("NO   Leave SSH unchanged\n     Then use: flotte ssh user@host", "manual"),
		).Value(&choice)
		if err := huh.NewForm(huh.NewGroup(form)).WithInput(in).WithOutput(out).RunWithContext(ctx); err != nil {
			return false, err
		}
		return choice == "setup", nil
	}
	fmt.Fprint(out, "\nSSH access setup\n  1. Configure SSH to use Flotte automatically\n     Then use: ssh user@host\n  2. Leave SSH unchanged\n     Then use: flotte ssh user@host\nChoose 1 or 2 [1]: ")
	return readSetupDecision(bufio.NewReader(in))
}

func readSetupDecision(reader *bufio.Reader) (bool, error) {
	input, err := reader.ReadString('\n')
	if err == io.EOF {
		return false, io.ErrUnexpectedEOF
	}
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "", "1", "a", "automatic", "y", "yes", "config", "setup":
		return true, nil
	case "2", "m", "manual", "n", "no", "flotte ssh":
		return false, nil
	case "\x03":
		return false, context.Canceled
	default:
		return false, fmt.Errorf("enter config or flotte ssh")
	}
}

func chooseCompletionInstallation(ctx context.Context, out io.Writer, in io.Reader, shell string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	choice := "install"
	fmt.Fprintln(out)
	form := huh.NewSelect[string]().Title(fmt.Sprintf("Install %s shell completion", shell)).Options(
		huh.NewOption("YES  Install completion", "install"),
		huh.NewOption("NO   Skip completion", "skip"),
	).Value(&choice)
	if err := huh.NewForm(huh.NewGroup(form)).WithInput(in).WithOutput(out).RunWithContext(ctx); err != nil {
		return false, err
	}
	return choice == "install", nil
}
