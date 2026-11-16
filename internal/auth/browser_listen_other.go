//go:build !windows

package auth

import "net"

func loopbackListenConfig() net.ListenConfig {
	return net.ListenConfig{}
}
