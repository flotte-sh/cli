package openssh

import (
	"context"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
)

func safeUpstreamAgentSocket(upstreamAgentSocket string) bool {
	upstreamAgentSocket = strings.ToLower(strings.ReplaceAll(upstreamAgentSocket, "/", `\`))
	return strings.HasPrefix(upstreamAgentSocket, `\\.\pipe\`) && !strings.HasPrefix(upstreamAgentSocket, `\\.\pipe\flotte-`)
}

func dialUpstreamAgentSocket(ctx context.Context, pipePath string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, pipePath)
}
