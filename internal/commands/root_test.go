package commands

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestArgumentFreeCommandsRejectArguments(t *testing.T) {
	for _, command := range []string{"login", "logout", "user", "version", "config"} {
		t.Run(command, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("USERPROFILE", t.TempDir())
			root := NewRoot("test")
			root.SetArgs([]string{command, "extra"})
			if err := root.ExecuteContext(t.Context()); err == nil {
				t.Fatalf("%s accepted an unexpected argument", command)
			}
		})
	}
}

func TestRootHelpShowsCommandsByPurpose(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	root := NewRoot("test")
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetArgs([]string{"--help"})
	if err := root.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}

	help := output.String()
	for _, expected := range []string{
		"GET STARTED",
		"setup",
		"ssh-config",
		"completion",
		"SSH CERTIFICATES",
		"cert",
		"ssh",
		"filezilla",
		"ACCOUNT",
		"config",
		"login",
		"logout",
		"user",
		"version",
	} {
		if !strings.Contains(help, expected) {
			t.Errorf("root help missing %q", expected)
		}
	}
	for _, hidden := range []string{"ssh-hostkeys", "ssh-agent-serve"} {
		if strings.Contains(help, hidden) {
			t.Errorf("root help exposes internal command %q", hidden)
		}
	}
}

func TestFileZillaCommandAvailability(t *testing.T) {
	root := NewRoot("test")
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"filezilla", "--help"})
	if err := root.ExecuteContext(t.Context()); err != nil {
		t.Fatalf("FileZilla command unavailable on %s: %v", runtime.GOOS, err)
	}
	if !strings.Contains(output.String(), "Allow SSH agent keys of unknown type") {
		t.Fatalf("FileZilla help omitted compatibility requirements: %s", output.String())
	}
}

func TestWinSCPCommandAvailability(t *testing.T) {
	root := NewRoot("test")
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"winscp", "--help"})
	err := root.ExecuteContext(t.Context())
	if runtime.GOOS == "windows" && err != nil {
		t.Fatalf("Windows rejected the WinSCP command: %v", err)
	}
	if runtime.GOOS != "windows" && err == nil {
		t.Fatalf("%s exposed the Windows-only WinSCP command", runtime.GOOS)
	}
}

func TestSshCompletionIncludesCommonOptions(t *testing.T) {
	root := NewRoot("test")
	cmd, _, err := root.Find([]string{"ssh"})
	if err != nil {
		t.Fatal(err)
	}
	completions, directive := cmd.ValidArgsFunction(cmd, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("completion directive = %v, want ShellCompDirectiveNoFileComp", directive)
	}
	for _, option := range []string{"-p", "-i", "-L"} {
		found := false
		for _, completion := range completions {
			if strings.HasPrefix(completion, option+"\t") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("completion missing %s", option)
		}
	}
}
