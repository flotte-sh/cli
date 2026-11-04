package start

import (
	"path/filepath"
	"strings"
)

func isSupportedShell(shell string) bool {
	switch shell {
	case shellBash, shellZsh, shellFish, shellPowerShell:
		return true
	default:
		return false
	}
}

func detectedShell(platform, loginShell string) string {
	if platform == "windows" {
		return shellPowerShell
	}
	for _, candidate := range []string{loginShell, shellBash} {
		if shell := shellName(candidate); shell != "" {
			return shell
		}
	}
	return shellBash
}

func shellName(name string) string {
	name = strings.TrimPrefix(filepath.Base(strings.TrimSpace(name)), "-")
	name = strings.TrimSuffix(strings.ToLower(name), ".exe")
	if name == "pwsh" {
		return shellPowerShell
	}
	if isSupportedShell(name) {
		return name
	}
	return ""
}
