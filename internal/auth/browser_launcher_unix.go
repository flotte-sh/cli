//go:build !windows && !darwin

package auth

import "os/exec"

func startBrowser(targetURL string) error {
	return exec.Command("xdg-open", targetURL).Start() //#nosec G204 -- targetURL is built by the CLI from the configured Flotte server URL
}
