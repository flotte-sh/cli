package openssh

import (
	"fmt"
	"os"
)

func RemoveConfigIfPresent() error {
	path, err := getSSHConfigPath()
	if err != nil {
		return err
	}
	content, err := os.ReadFile(path) // #nosec G304 -- getSshConfigPath returns the user's fixed SSH config path.
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read SSH config: %w", err)
	}
	if !sshConfigEntryPattern.Match(content) && !nativeSSHConfigPattern.Match(content) {
		return nil
	}
	return UninstallConfig()
}
