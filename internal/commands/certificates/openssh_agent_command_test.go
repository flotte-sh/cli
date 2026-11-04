package certificates

import (
	"bytes"
	"testing"
)

func TestSSHAgentServeIgnoresMalformedInvocation(t *testing.T) {
	for index, args := range [][]string{nil, {"too", "many"}, {"--unknown"}} {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			command := NewSSHAgentServeCmd()
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(&output)
			command.SetArgs(args)
			if err := command.ExecuteContext(t.Context()); err != nil {
				t.Fatalf("malformed invocation returned error: %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("malformed invocation produced output: %q", output.String())
			}
		})
	}
}
