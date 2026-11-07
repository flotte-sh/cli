package start

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/flotte-sh/cli/integrations/openssh"
	"github.com/spf13/cobra"
)

func TestUninstallIntegrations(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := &Root{Command: &cobra.Command{Use: "flotte"}}
	shells := []string{"bash", "zsh", "fish", "powershell"}
	for _, shell := range shells {
		if _, err := installCompletion(root, shell); err != nil {
			t.Fatal(err)
		}
	}
	sshPath := filepath.Join(home, ".ssh", "config")
	if err := os.MkdirAll(filepath.Dir(sshPath), 0o700); err != nil {
		t.Fatal(err)
	}
	otherConfig := "Host example\n  HostName example.org\n"
	if err := os.WriteFile(sshPath, []byte(otherConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openssh.InstallConfig(); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		cmd := NewUninstallCmd()
		if cmd.GroupID != "start" {
			t.Fatal("uninstall must share setup's group")
		}
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs(nil)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
	}
	for _, shell := range shells {
		path, err := completionPath(shell)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s completion remains: %v", shell, err)
		}
	}
	content, err := os.ReadFile(sshPath)
	if err != nil || string(content) != otherConfig {
		t.Fatalf("SSH config not preserved: %q, %v", content, err)
	}
}

func TestUninstallWithoutIntegrations(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cmd := NewUninstallCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatalf("uninstall created files: %v, %v", entries, err)
	}
}
