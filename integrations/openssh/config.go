package openssh

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	clierrors "github.com/flotte-sh/cli/internal/errors"
)

var (
	argv = os.Args
	goos = runtime.GOOS
)

func generateSSHConfig() (string, error) {
	const operation = "ssh-config.generate"
	options, err := nativeSSHOptions()
	if err != nil {
		return "", clierrors.Wrap(operation, err, "failed to derive the native SSH integration entry")
	}
	var entry strings.Builder
	entry.WriteString("# BEGIN FLOTTE OPENSSH\nHost *\n")
	entry.WriteString("\tKnownHostsCommand ")
	entry.WriteString(options.knownHostsCommand)
	entry.WriteByte('\n')
	entry.WriteString("\tIdentityAgent ")
	entry.WriteString(options.identityAgentOption)
	entry.WriteByte('\n')
	entry.WriteString("# END FLOTTE OPENSSH\n\n")
	return entry.String(), nil
}

func getSSHConfigPath() (string, error) {
	userHome, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(userHome, ".ssh", "config"), nil
}

func createSSHConfigIfMissing(path string) error {
	sshDir := filepath.Dir(path)
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return fmt.Errorf("failed to create SSH config directory %s: %w", sshDir, err)
	}

	if _, err := os.Stat(path); err == nil {
		return nil
	}
	f, err := os.Create(path) //#nosec G304 -- path is ~/.ssh/config from getSshConfigPath
	if err != nil {
		return err
	}
	defer f.Close()
	_ = f.Chmod(0o600)
	return nil
}

func readSSHConfig() (string, error) {
	sshConfigPath, err := getSSHConfigPath()
	if err != nil {
		return "", err
	}
	content, err := os.ReadFile(sshConfigPath) //#nosec G304 -- sshConfigPath is ~/.ssh/config from getSshConfigPath
	if err != nil {
		return "", err
	}

	return string(content), nil
}

var sshConfigEntryPattern = regexp.MustCompile(`(?m)^Match exec "[^\r\n]+ cert auto (?:'%r' '%h' '%p'|%r %h %p|\\"%r\\" \\"%h\\" \\"%p\\")"\r?\n\tCertificateFile ~/\.flotte/ssh/id_ed25519-cert\.pub\r?\n\tIdentityFile ~/\.flotte/ssh/id_ed25519\r?\n\tUserKnownHostsFile ~/\.flotte/ssh/known_hosts\r?\n\r?\n`)

func sshConfigHasEntry() (bool, error) {
	content, err := readSSHConfig()
	if err != nil {
		return false, err
	}

	return nativeSSHConfigPattern.MatchString(content) || sshConfigEntryPattern.MatchString(content), nil
}

func addToSSHConfig(entry string) error {
	path, err := getSSHConfigPath()
	if err != nil {
		return err
	}
	if err := createSSHConfigIfMissing(path); err != nil {
		return err
	}

	content, err := readSSHConfig()
	if err != nil {
		return err
	}

	content = sshConfigEntryPattern.ReplaceAllString(content, "")
	content = nativeSSHConfigPattern.ReplaceAllString(content, "")
	newContent := []byte(entry + content)
	if err := os.WriteFile(path, newContent, 0o600); err != nil {
		return err
	}

	return nil
}

func IsConfigured() (bool, error) {
	hasEntry, err := sshConfigHasEntry()
	if os.IsNotExist(err) {
		return false, nil
	}
	return hasEntry, err
}

// InstallStatus reports what InstallConfig did to the SSH config.
type InstallStatus int

const (
	// InstallStatusInstalled means a Flotte block was added.
	InstallStatusInstalled InstallStatus = iota
	// InstallStatusUpdated means an outdated Flotte block was replaced.
	InstallStatusUpdated
	// InstallStatusUnchanged means the Flotte block already matched.
	InstallStatusUnchanged
)

func InstallConfig() (InstallStatus, error) {
	const operation = "ssh-config.install"
	path, err := getSSHConfigPath()
	if err != nil {
		return 0, err
	}
	if err := createSSHConfigIfMissing(path); err != nil {
		return 0, err
	}
	content, err := readSSHConfig()
	if err != nil {
		return 0, err
	}
	entry, err := generateSSHConfig()
	if err != nil {
		return 0, err
	}

	hasLegacyEntry := sshConfigEntryPattern.MatchString(content)
	nativeBlocks := nativeSSHConfigPattern.FindAllString(content, -1)
	if len(nativeBlocks) == 0 {
		if err := addToSSHConfig(entry); err != nil {
			return 0, clierrors.Wrap(operation, err, "failed to add flotte entry to SSH config")
		}
		if hasLegacyEntry {
			return InstallStatusUpdated, nil
		}
		return InstallStatusInstalled, nil
	}
	if len(nativeBlocks) == 1 && !hasLegacyEntry && sameSSHConfigBlock(nativeBlocks[0], entry) {
		return InstallStatusUnchanged, nil
	}
	updated := []byte(replaceSSHConfigBlocks(content, entry))
	if err := os.WriteFile(path, updated, 0o600); err != nil { // #nosec G703 -- path is derived from the current user's home directory.
		return 0, clierrors.Wrap(operation, err, "failed to update flotte entry in SSH config")
	}
	return InstallStatusUpdated, nil
}

// sameSSHConfigBlock ignores line endings and trailing blank lines, which do not
// change what OpenSSH reads.
func sameSSHConfigBlock(a, b string) bool {
	normalize := func(block string) string {
		return strings.TrimRight(strings.ReplaceAll(block, "\r\n", "\n"), "\n")
	}
	return normalize(a) == normalize(b)
}

// replaceSSHConfigBlocks writes entry where the first Flotte block was, because
// OpenSSH uses the first value it reads, and removes any other Flotte blocks.
func replaceSSHConfigBlocks(content, entry string) string {
	content = sshConfigEntryPattern.ReplaceAllString(content, "")
	replaced := false
	return nativeSSHConfigPattern.ReplaceAllStringFunc(content, func(string) string {
		if replaced {
			return ""
		}
		replaced = true
		return entry
	})
}

func UninstallConfig() error {
	const operation = "ssh-config.uninstall"

	sshConfigPath, err := getSSHConfigPath()
	if err != nil {
		return clierrors.Wrap(operation, err, "failed to locate SSH config file")
	}

	config, err := os.ReadFile(sshConfigPath) // #nosec G304 -- getSSHConfigPath returns the user's fixed SSH config path.
	if os.IsNotExist(err) {
		return clierrors.New(operation, nil, "flotte SSH configuration not found")
	}
	if err != nil {
		return clierrors.Wrap(operation, err, "failed to read SSH config file")
	}
	configText := string(config)

	newConfig := sshConfigEntryPattern.ReplaceAllString(configText, "")
	newConfig = nativeSSHConfigPattern.ReplaceAllString(newConfig, "")
	if newConfig == configText {
		return clierrors.New(operation, nil, "flotte SSH configuration not found")
	}

	if err := os.WriteFile(sshConfigPath, []byte(newConfig), 0o600); err != nil { // #nosec G703 -- path is derived from the current user's home directory.
		return clierrors.Wrap(operation, err, "failed to write SSH config file")
	}

	return nil
}
