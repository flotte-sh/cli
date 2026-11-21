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
			printLoopbackInstructions(ctx, &loopbackLogin{authorizeURL: "https://example.test/login", port: 43123}, test.launchErr)
			if strings.Contains(out.String(), "https://example.test/login") != test.wantURL {
				t.Fatalf("unexpected URL visibility: %q", out.String())
			}
			if strings.Contains(out.String(), "|") {
				t.Fatalf("obsolete rails: %q", out.String())
			}
			if test.launchErr != nil && !strings.Contains(out.String(), "Could not open the browser") {
				t.Fatalf("missing browser failure warning: %q", out.String())
			}
			if test.wantURL && !strings.Contains(out.String(), "ssh -L 43123:127.0.0.1:43123") {
				t.Fatalf("missing remote machine hint: %q", out.String())
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
	printLoopbackInstructions(ctx, &loopbackLogin{authorizeURL: "https://example.test/login", port: 43123}, nil)
	if !strings.Contains(out.String(), "Visit: https://example.test/login") {
		t.Fatalf("default login output changed: %q", out.String())
	}
}
