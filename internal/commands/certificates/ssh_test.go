package certificates

import "testing"

func TestSSHHelpRequest(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		if !isSSHHelpRequest(args) {
			t.Errorf("isSSHHelpRequest(%q) = false", args)
		}
	}
	for _, args := range [][]string{nil, {"user@host"}, {"--help", "user@host"}} {
		if isSSHHelpRequest(args) {
			t.Errorf("isSSHHelpRequest(%q) = true", args)
		}
	}
}
