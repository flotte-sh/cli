package start

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

const (
	shellBash       = "bash"
	shellZsh        = "zsh"
	shellFish       = "fish"
	shellPowerShell = "powershell"
)

var supportedShells = []string{shellBash, shellZsh, shellFish, shellPowerShell}

func NewCompletionCmd(root *Root) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate or install shell completion",
		Example: `  flotte completion install [bash|zsh|fish|powershell]
  flotte completion uninstall [bash|zsh|fish|powershell]`,
		Args:      cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
		ValidArgs: supportedShells,
		RunE: func(cmd *cobra.Command, args []string) error {
			shell := detectedShell(runtime.GOOS, os.Getenv("SHELL"))
			if len(args) == 1 {
				shell = args[0]
			}
			return writeCompletion(cmd.OutOrStdout(), root, shell)
		},
	}
	cmd.AddCommand(completionInstallCommand(root))
	cmd.AddCommand(completionUninstallCommand())
	return cmd
}

func completionInstallCommand(root *Root) *cobra.Command {
	return &cobra.Command{
		Use:       "install [bash|zsh|fish|powershell]",
		Short:     "Install shell completion for the current user",
		Args:      cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
		ValidArgs: supportedShells,
		RunE: func(cmd *cobra.Command, args []string) error {
			shell := detectedShell(runtime.GOOS, os.Getenv("SHELL"))
			if len(args) == 1 {
				shell = args[0]
			}
			path, err := installCompletion(root, shell)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Installed %s completion to %s\n", shell, path)
			return nil
		},
	}
}

func completionUninstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:       "uninstall [bash|zsh|fish|powershell]",
		Short:     "Remove installed shell completion",
		Args:      cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
		ValidArgs: supportedShells,
		RunE: func(cmd *cobra.Command, args []string) error {
			shell := detectedShell(runtime.GOOS, os.Getenv("SHELL"))
			if len(args) == 1 {
				shell = args[0]
			}
			path, removed, err := removeCompletion(shell)
			if err != nil {
				return fmt.Errorf("remove completion file: %w", err)
			}
			if !removed {
				fmt.Fprintf(cmd.OutOrStdout(), "No %s completion installed at %s\n", shell, path)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s completion from %s. Restart your shell to unload it.\n", shell, path)
			return nil
		},
	}
}

func writeCompletion(out io.Writer, root *Root, shell string) error {
	switch shell {
	case shellBash:
		return root.GenBashCompletionV2(out, true)
	case shellZsh:
		return root.GenZshCompletionNoDesc(out)
	case shellFish:
		return root.GenFishCompletion(out, true)
	case shellPowerShell:
		return root.GenPowerShellCompletion(out)
	default:
		return fmt.Errorf("unsupported shell %q", shell)
	}
}

func completionPath(shell string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}

	var path string
	switch shell {
	case shellBash:
		path = filepath.Join(home, ".local", "share", "bash-completion", "completions", "flotte")
	case shellZsh:
		path = filepath.Join(home, ".zfunc", "_flotte")
	case shellFish:
		path = filepath.Join(home, ".config", "fish", "completions", "flotte.fish")
	case shellPowerShell:
		path = filepath.Join(home, "Documents", "PowerShell", "Scripts", "flotte-completion.ps1")
	default:
		return "", fmt.Errorf("unsupported shell %q", shell)
	}
	return path, nil
}

func isCompletionInstalled(shell string) bool {
	path, err := completionPath(shell)
	if err != nil {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func removeCompletion(shell string) (string, bool, error) {
	path, err := completionPath(shell)
	if err != nil {
		return "", false, err
	}
	if err := os.Remove(path); os.IsNotExist(err) {
		return path, false, nil
	} else if err != nil {
		return path, false, err
	}
	return path, true, nil
}

func installCompletion(root *Root, shell string) (string, error) {
	path, err := completionPath(shell)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create completion directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- completionPath selects a fixed shell-specific path under the user's home.
	if err != nil {
		return "", fmt.Errorf("open completion file: %w", err)
	}
	defer file.Close()
	if err := writeCompletion(file, root, shell); err != nil {
		return "", fmt.Errorf("generate %s completion: %w", shell, err)
	}
	return path, nil
}
