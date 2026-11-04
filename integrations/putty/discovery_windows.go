package putty

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func findPuTTY(explicitPath string) (string, error) {
	if explicitPath != "" {
		path, err := exec.LookPath(explicitPath)
		if err != nil {
			return "", fmt.Errorf("find PuTTY specified by --putty: %w", err)
		}
		return filepath.Abs(path)
	}
	if path, err := exec.LookPath("putty.exe"); err == nil {
		return filepath.Abs(path)
	}
	for _, variable := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
		base := os.Getenv(variable)
		if base == "" {
			continue
		}
		for _, directory := range []string{"PuTTY", filepath.Join("Programs", "PuTTY")} {
			candidate := filepath.Join(base, directory, "putty.exe")
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() { // #nosec G703 -- local installation paths come from the CLI user's environment.
				return filepath.Abs(candidate)
			}
		}
	}
	return "", fmt.Errorf("putty.exe not found; install PuTTY or specify --putty <path-to-putty.exe>")
}
