//go:build !windows

package openssh

import (
	"context"
	"net"
	"path/filepath"
	"strings"
)

func safeUpstreamAgentSocket(upstreamAgentSocket string) bool {
	if !filepath.IsAbs(upstreamAgentSocket) {
		return false
	}
	resolved, err := filepath.EvalSymlinks(upstreamAgentSocket)
	if err != nil {
		return false
	}
	endpointPrefix, err := agentEndpointPrefix()
	if err != nil {
		return false
	}
	endpointPrefix, err = filepath.EvalSymlinks(endpointPrefix)
	if err == nil && (resolved == endpointPrefix || strings.HasPrefix(resolved, endpointPrefix+string(filepath.Separator))) {
		return false
	}
	return !strings.HasPrefix(filepath.Base(filepath.Dir(resolved)), "flotte-agent-")
}

func dialUpstreamAgentSocket(ctx context.Context, socketPath string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
}
