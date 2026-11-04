package start

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestInteractiveCertificateMode(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	for _, test := range []struct {
		name    string
		input   string
		want    bool
		wantErr bool
	}{
		{"default automatic", "\r", true, false},
		{"manual with down", "\x1b[B\r", false, false},
		{"cancel", "\x03", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var out bytes.Buffer
			got, err := chooseCertificateMode(ctx, &out, strings.NewReader(test.input), true)
			if got != test.want || (err != nil) != test.wantErr {
				t.Fatalf("got %t, %v", got, err)
			}
			if ctx.Err() != nil {
				t.Fatal("selector timed out")
			}
		})
	}
}

func TestChooseCertificateMode(t *testing.T) {
	for _, test := range []struct {
		input   string
		want    bool
		wantErr bool
	}{
		{"automatic\n", true, false},
		{"manual\n", false, false},
		{"", false, true},
		{"automatic", false, true},
		{"\x03\n", false, true},
	} {
		var out bytes.Buffer
		got, err := chooseCertificateMode(context.Background(), &out, strings.NewReader(test.input), false)
		if got != test.want || (err != nil) != test.wantErr {
			t.Fatalf("input %q: %t, %v", test.input, got, err)
		}
		if strings.ContainsAny(out.String(), "|\x1b") {
			t.Fatalf("unexpected terminal output: %q", out.String())
		}
	}
}

func TestSetupHasShowLoginURLFlag(t *testing.T) {
	cmd := NewSetupCmd(nil)
	if cmd.Flags().Lookup("show-login-url") == nil {
		t.Fatal("missing login URL flag")
	}
	if cmd.Flags().Lookup("non-interactive") == nil {
		t.Fatal("missing non-interactive flag")
	}
	if cmd.Flags().Lookup("install-ssh-config") == nil {
		t.Fatal("missing install-ssh-config flag")
	}
	if cmd.Flags().Lookup("install-completion") == nil {
		t.Fatal("missing install-completion flag")
	}
	if err := cmd.Args(cmd, nil); err != nil {
		t.Fatalf("setup should allow an omitted URL: %v", err)
	}
	if err := cmd.Args(cmd, []string{"https://flotte.example.com"}); err != nil {
		t.Fatalf("setup should allow an explicit URL: %v", err)
	}
	if err := cmd.Args(cmd, []string{"https://one.example.com", "https://two.example.com"}); err == nil {
		t.Fatal("setup should reject multiple URLs")
	}
	_, directive := cmd.ValidArgsFunction(cmd, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("completion directive = %v, want ShellCompDirectiveNoFileComp", directive)
	}
}

func TestResolveSetupURL(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		savedURL     string
		wantURL      string
		wantErr      bool
		wantSentinel bool
	}{
		{
			name:     "uses saved URL when omitted",
			savedURL: "https://flotte.example.com/",
			wantURL:  "https://flotte.example.com",
		},
		{
			name:     "explicit URL overrides saved URL",
			args:     []string{"other.example.com"},
			savedURL: "https://flotte.example.com",
			wantURL:  "https://other.example.com",
		},
		{
			name:         "requires URL on first setup",
			wantErr:      true,
			wantSentinel: true,
		},
		{
			name:    "rejects invalid explicit URL",
			args:    []string{"https://"},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveSetupURL(test.args, test.savedURL)
			if (err != nil) != test.wantErr {
				t.Fatalf("resolveSetupURL() error = %v, want error: %t", err, test.wantErr)
			}
			if test.wantSentinel && err != errSetupURLNotConfigured {
				t.Fatalf("resolveSetupURL() error = %v, want missing URL sentinel", err)
			}
			if err == nil && got != test.wantURL {
				t.Fatalf("resolveSetupURL() = %q, want %q", got, test.wantURL)
			}
		})
	}
}

func TestMaskSetupEmail(t *testing.T) {
	for input, want := range map[string]string{
		"alice@example.com": "al**e@example.com",
		"abc":               "abc",
		"ab":                "**",
		"":                  "",
	} {
		if got := maskSetupEmail(input); got != want {
			t.Errorf("maskSetupEmail(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestReadSetupDecision(t *testing.T) {
	for _, test := range []struct {
		input   string
		want    bool
		invalid bool
	}{
		{"", false, true},
		{"yes", false, true},
		{"automatic\n", true, false},
		{"manual\n", false, false},
		{"\x03\n", false, true},
		{"\n", true, false},
		{"yes\n", true, false},
		{"Y\n", true, false},
		{"no\n", false, false},
		{"n\n", false, false},
		{"maybe\n", false, true},
	} {
		got, err := readSetupDecision(bufio.NewReader(strings.NewReader(test.input)))
		if got != test.want || (err != nil) != test.invalid {
			t.Errorf("input %q: got %t, %v", test.input, got, err)
		}
	}
}
