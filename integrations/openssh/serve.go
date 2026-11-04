package openssh

import (
	"context"
	"io"
)

func Serve(ctx context.Context, input io.Reader, output io.Writer, connectionHash string) error {
	paths, err := nativeSSHPaths()
	if err != nil {
		return err
	}
	return ServeAgent(ctx, input, output, paths.agentEndpointPrefix, connectionHash)
}
