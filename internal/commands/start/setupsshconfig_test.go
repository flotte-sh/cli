package start

import "testing"

func TestSshConfigCommandsRejectArguments(t *testing.T) {
	for _, subcommand := range []string{"install", "uninstall"} {
		t.Run(subcommand, func(t *testing.T) {
			cmd := NewSSHConfigCmd()
			cmd.SetArgs([]string{subcommand, "extra"})
			if err := cmd.Execute(); err == nil {
				t.Fatalf("ssh-config %s accepted an unexpected argument", subcommand)
			}
		})
	}
}
