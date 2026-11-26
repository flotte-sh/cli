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

	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/config"
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

func runSetup(t *testing.T, serverURL string) (string, error) {
	t.Helper()
	var output bytes.Buffer
	cmd := NewSetupCmd(&Root{Command: &cobra.Command{Use: "flotte"}})
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetContext(t.Context())
	cmd.SetArgs([]string{serverURL, "--non-interactive"})
	err := cmd.Execute()
	return output.String(), err
}

func TestSetupRefusesAServerAddressOnAnotherHost(t *testing.T) {
	keyring.MockInit()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		elsewhere.Add(1)
	}))
	defer other.Close()
	var withSession atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-flotte-token") != "" {
			withSession.Add(1)
		}
		if r.URL.Path == "/.well-known/cli-config" {
			fmt.Fprintf(w, `{"baseUrl":%q,"authMethods":["consent"]}`, other.URL)
			return
		}
		fmt.Fprint(w, `{"authenticated":true,"email":"user@example.com"}`)
	}))
	defer server.Close()
	cfg := config.ClientConfig{FlotteUrl: server.URL}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveToken(server.URL, "cached-token"); err != nil {
		t.Fatal(err)
	}

	_, err := runSetup(t, server.URL)

	if err == nil || !strings.Contains(err.Error(), "flotte setup "+other.URL) || !strings.Contains(err.Error(), "did not switch") {
		t.Fatalf("setup error = %v", err)
	}
	if elsewhere.Load() != 0 || withSession.Load() != 0 {
		t.Fatalf("requests to the reported address = %d, requests carrying the session = %d", elsewhere.Load(), withSession.Load())
	}
	saved, err := config.LoadOrCreate()
	if err != nil || saved.FlotteUrl != server.URL {
		t.Fatalf("saved configuration = %+v, %v", saved, err)
	}
	if token, err := auth.LoadToken(server.URL); err != nil || token != "cached-token" {
		t.Fatalf("cached session = %q, %v", token, err)
	}
}

func TestSetupKeepsTheSessionOfTheSameServer(t *testing.T) {
	keyring.MockInit()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SHELL", "/bin/bash")
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/cli-config" {
			fmt.Fprintf(w, `{"baseUrl":%q,"authMethods":["consent"]}`, server.URL+"/")
			return
		}
		fmt.Fprintf(w, `{"authenticated":%t,"email":"user@example.com"}`, r.Header.Get("X-flotte-token") == "cached-token")
	}))
	defer server.Close()
	if err := auth.SaveToken(server.URL, "cached-token"); err != nil {
		t.Fatal(err)
	}

	output, err := runSetup(t, server.URL)

	if err != nil || !strings.Contains(output, "Setup complete") {
		t.Fatalf("setup = %q, %v", output, err)
	}
	saved, err := config.LoadOrCreate()
	if err != nil || saved.FlotteUrl != server.URL {
		t.Fatalf("saved configuration = %+v, %v", saved, err)
	}
}
