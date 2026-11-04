//go:build darwin

package auth

import "os/exec"

func startBrowser(targetURL string) error {
	return exec.Command("open", targetURL).Start() //#nosec G204 -- targetURL comes from the backend's authenticated broker endpoint
}
