package winscp

import (
	"context"
	"os/exec"
	"syscall"
)

func winSCPProcess(ctx context.Context, executable string, arguments []string) *exec.Cmd {
	process := exec.CommandContext(ctx, executable, arguments...) // #nosec G204 -- The local CLI user selects the executable; session arguments are passed without a shell.
	process.SysProcAttr = &syscall.SysProcAttr{CmdLine: winSCPCommandLine(process.Args)}
	return process
}
