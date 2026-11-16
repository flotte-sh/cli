//go:build windows

package auth

import (
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// SO_EXCLUSIVEADDRUSE is defined by Winsock as the bitwise complement of
// SO_REUSEADDR; x/sys/windows does not export it. Without it another local
// process could bind the same loopback port and receive the sign-in response
// (RFC 8252, appendix B.3).
const soExclusiveAddrUse = ^windows.SO_REUSEADDR

func loopbackListenConfig() net.ListenConfig {
	return net.ListenConfig{
		Control: func(_, _ string, conn syscall.RawConn) error {
			var optionErr error
			if err := conn.Control(func(fd uintptr) {
				optionErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
			}); err != nil {
				return err
			}
			return optionErr
		},
	}
}
