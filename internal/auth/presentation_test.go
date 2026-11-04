package auth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestBrowserPresentation(t *testing.T) {
	for _, test := range []struct {
		name      string
		show      bool
		launchErr error
		wantURL   bool
	}{
		{"setup browser", false, nil, false},
		{"explicit URL", true, nil, true},
		{"failed browser", false, errors.New("unavailable"), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			ctx := WithPresentation(context.Background(), &out, test.show)
			printBrowserInstructions(ctx, "https://example.test/login", test.launchErr)
			if strings.Contains(out.String(), "https://example.test/login") != test.wantURL {
				t.Fatalf("unexpected URL visibility: %q", out.String())
			}
			if strings.Contains(out.String(), "|") {
				t.Fatalf("obsolete rails: %q", out.String())
			}
			if test.launchErr != nil && !strings.Contains(out.String(), "Could not open the browser") {
				t.Fatalf("missing browser failure warning: %q", out.String())
			}
			if !test.wantURL && !strings.Contains(out.String(), "--show-login-url") {
				t.Fatalf("missing URL fallback: %q", out.String())
			}
		})
	}
	if !showLoginURL(context.Background()) {
		t.Fatal("other callers must retain URLs")
	}
}

func TestDefaultBrowserPresentation(t *testing.T) {
	var out bytes.Buffer
	ctx := context.WithValue(context.Background(), presentationWriterKey{}, &out)
	printBrowserInstructions(ctx, "https://example.test/login", nil)
	if !strings.Contains(out.String(), "Visit: https://example.test/login") {
		t.Fatalf("default login output changed: %q", out.String())
	}
}
