//go:build windows

package commands

import "github.com/flotte-sh/cli/internal/commands/certificates"

func registerPlatformCommands(r *Root) {
	addCommands(r, "certificates", certificates.NewWinSCPCmd(r), certificates.NewPuttyCmd(r))
}
