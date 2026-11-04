package certificates

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flotte-sh/flotte-cli/integrations/openssh"
	"github.com/flotte-sh/flotte-cli/internal/auth"
	"github.com/flotte-sh/flotte-cli/internal/client"
	"github.com/flotte-sh/flotte-cli/internal/config"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

func TestSSHHostkeysFailClosed(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	for _, test := range []struct {
		name         string
		status       int
		body         string
		authStatus   int
		unconfigured bool
		outage       bool
		allow        bool
	}{
		{name: "unknown server", status: 404, body: `{"error":"server not found"}`, allow: true},
		{name: "missing login", status: 404, body: `{"error":"no login configured for this user on the server"}`},
		{name: "missing user", status: 404, body: `{"error":"user not found"}`},
		{name: "generic 404", status: 404, body: `not found`},
		{name: "plaintext unknown server", status: 404, body: `server not found`},
		{name: "forbidden", status: 403, body: `{"error":"server not found"}`},
		{name: "server error", status: 500, body: `{"error":"server not found"}`},
		{name: "unauthorized", status: 401, body: `{"error":"session expired"}`},
		{name: "malformed success", status: 200, body: `invalid`},
		{name: "empty host keys", status: 200, body: `{"hostkeys":[]}`},
		{name: "invalid host key", status: 200, body: `{"hostkeys":["invalid"]}`},
		{name: "mismatched host key", status: 200},
		{name: "auth expired", authStatus: 401},
		{name: "auth outage", authStatus: 503},
		{name: "auth unknown server", authStatus: 404},
		{name: "unconfigured", unconfigured: true},
		{name: "network outage", outage: true, allow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			keyring.MockInit()
			if err := auth.SaveToken("cached-token"); err != nil {
				t.Fatal(err)
			}
			private, err := openssh.LoadCLIPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			presented, err := ssh.NewPublicKey(private.Public())
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/auth/me" {
					if test.authStatus != 0 {
						writer.WriteHeader(test.authStatus)
						fmt.Fprint(writer, `{"error":"server not found"}`)
						return
					}
					fmt.Fprint(writer, `{"authenticated":true}`)
					return
				}
				if request.URL.Path != "/ssh/cert" {
					http.NotFound(writer, request)
					return
				}
				writer.WriteHeader(test.status)
				if test.name == "mismatched host key" {
					certificate := &ssh.Certificate{Key: presented, CertType: ssh.HostCert, SignatureKey: presented, Signature: &ssh.Signature{Format: presented.Type(), Blob: []byte("test")}}
					_ = json.NewEncoder(writer).Encode(client.SshCertResponse{Hostkeys: []string{string(ssh.MarshalAuthorizedKey(certificate))}})
					return
				}
				fmt.Fprint(writer, test.body)
			}))
			defer server.Close()
			if test.outage {
				server.Close()
			}
			root := &Root{Config: &config.ClientConfig{FlotteUrl: server.URL}}
			if test.unconfigured {
				root.Config = nil
			}
			command := NewSSHHostkeysCmd(root)
			command.SetContext(t.Context())
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(&output)
			err = command.RunE(command, []string{"HOSTNAME", "example.test", "alice", presented.Type(), base64.StdEncoding.EncodeToString(presented.Marshal()), strings.Repeat("a", 40)})
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if test.allow && output.Len() != 0 {
				t.Fatalf("unexpected host-key output: %q", output.String())
			}
			if !test.allow && output.Len() == 0 {
				t.Fatal("expected error output")
			}
		})
	}
}
