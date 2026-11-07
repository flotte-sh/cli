package account

import (
	"bytes"
	"strings"
	"testing"

	"github.com/flotte-sh/cli/internal/config"
)

func TestConfigHasNoAuthModeOptionOrDisplay(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := (&config.ClientConfig{FlotteUrl: "https://example.com"}).Save(); err != nil {
		t.Fatal(err)
	}
	cmd := NewConfigCmd(nil)
	if cmd.Flags().Lookup("auth-mode") != nil || strings.Contains(cmd.Example, "auth-mode") {
		t.Fatal("auth-mode still exposed")
	}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--show"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out.String()), "auth") {
		t.Fatalf("auth displayed: %s", out.String())
	}
}
