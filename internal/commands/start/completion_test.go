package start

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCompletionUninstall(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	root := &Root{Command: &cobra.Command{Use: "flotte"}}
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			if isCompletionInstalled(shell) {
				t.Fatal("missing completion detected as installed")
			}
			path, err := installCompletion(root, shell)
			if err != nil {
				t.Fatal(err)
			}
			if !isCompletionInstalled(shell) {
				t.Fatal("installed completion not detected")
			}
			neighbor := filepath.Join(filepath.Dir(path), "other-completion")
			if err := os.WriteFile(neighbor, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				cmd := completionUninstallCommand()
				cmd.SetOut(&bytes.Buffer{})
				cmd.SetArgs([]string{shell})
				if err := cmd.Execute(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("completion still exists: %v", err)
			}
			if isCompletionInstalled(shell) {
				t.Fatal("removed completion detected as installed")
			}
			if content, err := os.ReadFile(neighbor); err != nil || string(content) != "keep" {
				t.Fatalf("neighbor changed: %v", err)
			}
		})
	}
	cmd := completionUninstallCommand()
	cmd.SetArgs([]string{"unsupported"})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err == nil {
		t.Fatal("unsupported shell accepted")
	}
}

func TestCompletionSupportsAllShells(t *testing.T) {
	root := &Root{Command: &cobra.Command{Use: "flotte"}}
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			var output bytes.Buffer
			if err := writeCompletion(&output, root, shell); err != nil {
				t.Fatalf("writeCompletion(%q): %v", shell, err)
			}
			if !strings.Contains(output.String(), "flotte") {
				t.Fatalf("writeCompletion(%q) did not generate flotte completion", shell)
			}
		})
	}
}

func TestCompletionCommandGeneratesScript(t *testing.T) {
	root := &Root{Command: &cobra.Command{Use: "flotte"}}
	cmd := NewCompletionCmd(root)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"fish"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "flotte") {
		t.Fatal("completion command did not generate a script")
	}
}

func TestCompletionHelpShowsFullCommands(t *testing.T) {
	root := &Root{Command: &cobra.Command{Use: "flotte"}}
	cmd := NewCompletionCmd(root)
	root.AddCommand(cmd)
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetArgs([]string{"completion", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"flotte completion install [bash|zsh|fish|powershell]",
		"flotte completion uninstall [bash|zsh|fish|powershell]",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("completion help missing %q", want)
		}
	}
}

func TestDetectShell(t *testing.T) {
	if got := detectedShell("darwin", "/bin/zsh"); got != "zsh" {
		t.Fatalf("detectedShell() = %q, want zsh", got)
	}
	if got := detectedShell("linux", "/usr/bin/fish"); got != "fish" {
		t.Fatalf("detectedShell() = %q, want fish", got)
	}
	if got := detectedShell("windows", ""); got != "powershell" {
		t.Fatalf("Windows detectedShell() = %q, want powershell", got)
	}
}

func TestShellName(t *testing.T) {
	for input, want := range map[string]string{
		"/bin/bash":        "bash",
		"-zsh":             "zsh",
		"/usr/local/fish":  "fish",
		"pwsh":             "powershell",
		"PowerShell.exe":   "powershell",
		"terminal-wrapper": "",
	} {
		if got := shellName(input); got != want {
			t.Errorf("shellName(%q) = %q, want %q", input, got, want)
		}
	}
}
