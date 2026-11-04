//go:build windows

package pageant

import (
	"regexp"
	"testing"
)

func TestPipePathFormat(t *testing.T) {
	path, err := PipePath("alice")
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`^\\\\\.\\pipe\\pageant\.alice\.[0-9a-f]{64}$`)
	if !pattern.MatchString(path) {
		t.Fatalf("unexpected Pageant pipe path: %q", path)
	}
}

func TestCurrentUserPipePathUsesCurrentUsername(t *testing.T) {
	username, err := currentUsername()
	if err != nil {
		t.Fatal(err)
	}
	path, err := CurrentUserPipePath()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := PipePath(username)
	if err != nil {
		t.Fatal(err)
	}
	if path != expected {
		t.Fatalf("CurrentUserPipePath() = %q, want %q", path, expected)
	}
}
