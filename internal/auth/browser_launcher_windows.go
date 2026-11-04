//go:build windows

package auth

import (
	"fmt"
	"syscall"
	"unsafe"
)

var shellExecuteW = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")

func startBrowser(targetURL string) error {
	verb, err := syscall.UTF16PtrFromString("open")
	if err != nil {
		return fmt.Errorf("failed to prepare ShellExecute verb: %w", err)
	}
	target, err := syscall.UTF16PtrFromString(targetURL)
	if err != nil {
		return fmt.Errorf("failed to prepare ShellExecute target: %w", err)
	}
	result, _, callErr := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(target)),
		0,
		0,
		1,
	)
	if result <= 32 {
		if callErr != syscall.Errno(0) {
			return fmt.Errorf("failed to open browser: %w", callErr)
		}
		return fmt.Errorf("failed to open browser: ShellExecute returned %d", result)
	}
	return nil
}
