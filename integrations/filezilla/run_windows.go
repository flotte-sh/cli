//go:build windows

package filezilla

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/flotte-sh/cli/integrations/internal/pageant"
)

func listenAgentEndpoint() (agentEndpoint, error) {
	listener, _, err := pageant.Listen()
	if err != nil {
		return agentEndpoint{}, fmt.Errorf("cannot exclusively create Pageant agent endpoint; stop Pageant or another Flotte desktop launcher and retry: %w", err)
	}
	return agentEndpoint{
		listener: listener,
		close:    func() { _ = listener.Close() },
		configureProcess: func(command *exec.Cmd) {
			command.Env = setEnvironment(os.Environ(), "SSH_AUTH_SOCK", "")
		},
	}, nil
}

func setEnvironment(environment []string, name, value string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, name) {
			result = append(result, entry)
		}
	}
	if value != "" {
		result = append(result, name+"="+value)
	}
	return result
}
