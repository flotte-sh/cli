package config

import (
	"os"
	"strings"
	"testing"
)

func TestLegacyAuthModeIsIgnoredAndNotSaved(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path, err := EnsureStoragePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"flotteUrl":"https://example.com","authMode":{"invalid":"ignored"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "authMode") || cfg.FlotteUrl != "https://example.com" {
		t.Fatalf("saved config: %s", data)
	}
}
