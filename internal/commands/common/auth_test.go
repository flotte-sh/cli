package common

import (
	"context"
	"testing"

	"github.com/flotte-sh/flotte-cli/internal/config"
)

func TestRequireConfigAndAuthLoadsSavedConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := (&config.ClientConfig{FlotteUrl: "https://example.com"}).Save(); err != nil {
		t.Fatal(err)
	}

	root := &Root{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = RequireConfigAndAuth(root, ctx, "user", false)
	if root.Config == nil || root.Config.FlotteUrl != "https://example.com" {
		t.Fatalf("saved config not loaded: %+v", root.Config)
	}
}
