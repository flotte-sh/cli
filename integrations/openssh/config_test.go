package openssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSshConfigLifecycleAcrossExecutablePaths(t *testing.T) {
	originalArgs, originalGOOS := argv, goos
	t.Cleanup(func() { argv, goos = originalArgs, originalGOOS })
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	goos = "linux"
	argv = []string{"/tmp/go-build123/b001/exe/flotte"}
	if err := InstallConfig(); err != nil {
		t.Fatal(err)
	}
	argv = []string{"/usr/local/bin/flotte"}
	configured, err := IsConfigured()
	if err != nil || !configured {
		t.Error("installed config was not detected after executable changed")
	}
	if err := InstallConfig(); err == nil {
		t.Error("installed duplicate config after executable changed")
	}
	if err := UninstallConfig(); err != nil {
		t.Fatal(err)
	}
	configured, err = IsConfigured()
	if err != nil || configured {
		t.Error("config still detected after uninstall")
	}
	if err := UninstallConfig(); err == nil {
		t.Error("second uninstall should report missing config")
	}
}

func TestSSHConfigDetectionDoesNotCreateConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	configured, err := IsConfigured()
	if err != nil {
		t.Fatal(err)
	}
	if configured {
		t.Fatal("SSH config reported as installed")
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "config")); !os.IsNotExist(err) {
		t.Fatalf("SSH config detection created a file: %v", err)
	}
}

func TestGenerateSshConfigQuotesExecArguments(t *testing.T) {
	originalArgs := argv
	originalGOOS := goos
	argv = []string{"/tmp/$(touch pwn)/flotte"}
	goos = "linux"
	t.Cleanup(func() {
		argv = originalArgs
		goos = originalGOOS
	})

	cfg, err := generateSSHConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, `KnownHostsCommand "/tmp/$(touch pwn)/flotte" ssh-hostkeys %I %H %r %t %K %C`) {
		t.Fatalf("generateSshConfig() did not quote match exec arguments safely: %q", cfg)
	}
}

func TestGenerateSshConfigQuotesExecutableWithSingleQuote(t *testing.T) {
	originalArgs := argv
	originalGOOS := goos
	argv = []string{"/tmp/o'hare/flotte"}
	goos = "linux"
	t.Cleanup(func() {
		argv = originalArgs
		goos = originalGOOS
	})

	cfg, err := generateSSHConfig()
	if err != nil {
		t.Fatal(err)
	}
	wantExecLine := `KnownHostsCommand "/tmp/o'hare/flotte" ssh-hostkeys %I %H %r %t %K %C`
	if !strings.Contains(cfg, wantExecLine) {
		t.Fatalf("generateSshConfig() did not escape single quote in executable path: %q", cfg)
	}
}

func TestGenerateSshConfigQuotesMacOSExecutablePath(t *testing.T) {
	originalArgs := argv
	originalGOOS := goos
	argv = []string{"/Applications/Flotte App/flotte"}
	goos = "darwin"
	t.Cleanup(func() {
		argv = originalArgs
		goos = originalGOOS
	})

	cfg, err := generateSSHConfig()
	if err != nil {
		t.Fatal(err)
	}
	wantExecLine := `KnownHostsCommand "/Applications/Flotte App/flotte" ssh-hostkeys %I %H %r %t %K %C`
	if !strings.Contains(cfg, wantExecLine) {
		t.Fatalf("generateSshConfig() did not quote macOS executable path: %q", cfg)
	}
}

func TestGenerateSshConfigQuotesWindowsExecutablePath(t *testing.T) {
	originalArgs := argv
	originalGOOS := goos
	argv = []string{`/Program Files/flotte.exe`}
	goos = "windows"
	t.Cleanup(func() {
		argv = originalArgs
		goos = originalGOOS
	})

	cfg, err := generateSSHConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, `KnownHostsCommand "/Program Files/flotte.exe" ssh-hostkeys %I %H %r %t %K %C`) {
		t.Fatalf("generateSSHConfig() missing Windows KnownHostsCommand entry: %q", cfg)
	}
}

func TestGenerateSshConfigContainsExpectedSshSettings(t *testing.T) {
	cfg, err := generateSSHConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"KnownHostsCommand ", "IdentityAgent "} {
		if !strings.Contains(cfg, line) {
			t.Fatalf("missing expected line %q in %q", line, cfg)
		}
	}
	for _, line := range []string{"Match exec ", "CertificateFile ", "IdentityFile ", "UserKnownHostsFile "} {
		if strings.Contains(cfg, line) {
			t.Fatalf("unexpected line %q in %q", line, cfg)
		}
	}
}

func TestNativeSshConfigParsesWithOpenSSH(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is not installed")
	}
	originalArgs, originalGOOS := argv, goos
	t.Cleanup(func() { argv, goos = originalArgs, originalGOOS })
	argv, goos = []string{"/tmp/flotte"}, "linux"
	configuration, err := generateSSHConfig()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), ssh, "-G", "-F", path, "test.invalid").CombinedOutput()
	if err != nil {
		t.Fatalf("SSH rejected generated config: %v\n%s", err, output)
	}
}

func TestNativeSSHConfigMigratesLegacy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path, err := getSSHConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := createSSHConfigIfMissing(path); err != nil {
		t.Fatal(err)
	}
	legacy := "Match exec \"'/tmp/flotte' cert auto '%r' '%h' '%p'\"\n\tCertificateFile ~/.flotte/ssh/id_ed25519-cert.pub\n\tIdentityFile ~/.flotte/ssh/id_ed25519\n\tUserKnownHostsFile ~/.flotte/ssh/known_hosts\n\n"
	custom := "Host example\n\tUser alice\n"
	if err := os.WriteFile(path, []byte(legacy+custom), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallConfig(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(content), "cert auto") || !strings.HasSuffix(string(content), custom) || !nativeSSHConfigPattern.Match(content) {
		t.Fatalf("migration: %q, %v", content, err)
	}
	if err := UninstallConfig(); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(path)
	if err != nil || string(content) != custom {
		t.Fatalf("uninstall: %q, %v", content, err)
	}
}

func TestWindowsUninstallLegacySshConfig(t *testing.T) {
	settings := "\tCertificateFile ~/.flotte/ssh/id_ed25519-cert.pub\n\tIdentityFile ~/.flotte/ssh/id_ed25519\n\tUserKnownHostsFile ~/.flotte/ssh/known_hosts\n\n"
	legacy := `Match exec "cmd.exe /d /s /c \"C:\\Users\\Docker\\.ssh\\flotte.exe\" cert auto \"%r\" \"%h\" \"%p\""` + "\n" + settings
	for _, block := range []string{legacy} {
		for _, newline := range []string{"\n", "\r\n"} {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			path, err := getSSHConfigPath()
			if err != nil {
				t.Fatal(err)
			}
			if err := createSSHConfigIfMissing(path); err != nil {
				t.Fatal(err)
			}
			userConfig := "Host example\r\n\tUser alice\r\n"
			content := strings.ReplaceAll(block+block, "\n", newline) + userConfig
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := UninstallConfig(); err != nil {
				t.Fatal(err)
			}
			remaining, err := os.ReadFile(path)
			if err != nil || string(remaining) != userConfig {
				t.Fatalf("remaining = %q, error = %v", remaining, err)
			}
		}
	}
}
