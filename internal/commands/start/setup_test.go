package start

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
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
	if cmd.Flags().Lookup("device") == nil {
		t.Fatal("missing device flag")
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

func TestSetupUsesDeviceSignInOnlyWithTheDeviceFlag(t *testing.T) {
	for _, tt := range []struct {
		name       string
		args       []string
		wantDevice bool
	}{
		{"without the flag", nil, false},
		{"with the flag", []string{"--device"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			t.Setenv("HOME", t.TempDir())
			var deviceStarts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/cli-config":
					fmt.Fprint(w, `{"authMethods":["browser","device"],"preferredAuthMethod":"device","authMode":"device"}`)
				case "/auth/cli/device/start":
					deviceStarts.Add(1)
					fmt.Fprint(w, `{"deviceCode":"device-code","userCode":"ABCD-EFGH","verificationUri":"https://idp.example/device"}`)
				case "/auth/cli/device/token":
					fmt.Fprint(w, `{"token":"device-session","pending":false}`)
				case "/auth/me":
					fmt.Fprintf(w, `{"authenticated":%t,"email":"dev@example.com"}`, r.Header.Get("X-flotte-token") == "device-session")
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
				}
			}))
			defer server.Close()

			cmd := NewSetupCmd(&Root{})
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(append([]string{server.URL, "--non-interactive"}, tt.args...))
			err := cmd.ExecuteContext(t.Context())
			if !tt.wantDevice {
				if err == nil || !strings.Contains(err.Error(), "flotte login --device") {
					t.Fatalf("setup error = %v, want the --device hint", err)
				}
				if deviceStarts.Load() != 0 {
					t.Fatal("device sign-in started without --device")
				}
				return
			}
			if err != nil {
				t.Fatalf("setup --device: %v\n%s", err, out.String())
			}
			if deviceStarts.Load() != 1 || !strings.Contains(out.String(), "ABCD-EFGH") {
				t.Fatalf("device starts = %d, output = %q", deviceStarts.Load(), out.String())
			}
		})
	}
}
