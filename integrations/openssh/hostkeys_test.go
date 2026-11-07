package openssh

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/client"
	"github.com/flotte-sh/cli/internal/config"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

func TestSSHHostkeysUnknownServerIgnoresAgentProvisioningFailure(t *testing.T) {
	originalStartCertificateAgent := startCertificateAgent
	t.Cleanup(func() { startCertificateAgent = originalStartCertificateAgent })
	startCertificateAgent = func(string, Credential) error {
		return errors.New("agent unavailable")
	}
	t.Setenv("SSH_AUTH_SOCK", "/tmp/user-agent")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	keyring.MockInit()
	if err := auth.SaveToken("cached-token"); err != nil {
		t.Fatal(err)
	}
	private, err := LoadCLIPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	presented, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth/me" {
			_, _ = writer.Write([]byte(`{"authenticated":true}`))
			return
		}
		writer.WriteHeader(http.StatusNotFound)
		_, _ = writer.Write([]byte(`{"error":"server not found"}`))
	}))
	defer server.Close()
	cfg := &config.ClientConfig{FlotteUrl: server.URL}
	session := Session{
		Authenticate: func(context.Context, string, bool) (string, error) { return "cached-token", nil },
		RequestCertificate: func(ctx context.Context, token, publicKey, hostKey, loginUser string) (*client.SshCertResponse, error) {
			return client.RequestCertificate(ctx, cfg, token, publicKey, hostKey, loginUser)
		},
	}
	err = Hostkeys(t.Context(), io.Discard, io.Discard, []string{"HOSTNAME", "example.test", "alice", presented.Type(), base64.StdEncoding.EncodeToString(presented.Marshal()), strings.Repeat("a", 40)}, session)
	if err != nil {
		t.Fatalf("unknown server returned an error: %v", err)
	}
}
