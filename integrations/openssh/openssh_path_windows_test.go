package openssh

import (
	"os/exec"
	"strings"
	"testing"
)

func TestWindowsPipePathFitsOpenSSH(t *testing.T) {
	prefix, err := agentEndpointPrefix()
	if err != nil {
		t.Fatal(err)
	}
	path := agentEndpointPath(prefix, strings.Repeat("0", 40))
	if !strings.HasPrefix(path, `\\.\pipe\flotte-`) || strings.Contains(path[4:], `\\`) || len(path) >= 104 {
		t.Fatalf("invalid OpenSSH pipe path: %q", path)
	}
}

func TestWindowsOpenSSHParsesAgentPath(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is not installed")
	}
	options, err := nativeSSHOptions()
	if err != nil {
		t.Fatal(err)
	}
	arguments := makeNativeSSHArguments(options, []string{"-G", "-F", "none", "example.com"})
	output, err := exec.Command(ssh, arguments...).Output()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		if !strings.HasPrefix(line, "identityagent ") {
			continue
		}
		path := strings.TrimSpace(strings.TrimPrefix(line, "identityagent "))
		if !strings.HasPrefix(path, "//./pipe/flotte-") || strings.Contains(path, `\`) {
			t.Fatalf("OpenSSH parsed an invalid agent path: %q", path)
		}
		return
	}
	t.Fatal("OpenSSH configuration did not contain IdentityAgent")
}
