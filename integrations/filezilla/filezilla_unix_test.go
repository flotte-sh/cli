//go:build !windows

package filezilla

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/flotte-sh/cli/internal/client"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestRunFileZillaAgentSession(t *testing.T) {
	serverSigner := testSigner(t, 21)
	hostkey := string(ssh.MarshalAuthorizedKey(serverSigner.PublicKey()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sshServer := &ssh.ServerConfig{NoClientAuth: true}
	sshServer.AddHostKey(serverSigner)
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				server, channels, requests, handshakeErr := ssh.NewServerConn(connection, sshServer)
				if handshakeErr != nil {
					return
				}
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					_ = channel.Reject(ssh.UnknownChannelType, "hostkey probe only")
				}
				_ = server.Close()
			}()
		}
	}()

	caSigner := testSigner(t, 22)
	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/ssh/cert" || request.Header.Get("X-flotte-token") != "test-token" {
			http.Error(writer, "invalid certificate request", http.StatusBadRequest)
			return
		}
		var input client.SshCertRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			http.Error(writer, "invalid request body", http.StatusBadRequest)
			return
		}
		if input.ServerUser != "alice" || input.ServerHostkey != strings.TrimSpace(hostkey) {
			http.Error(writer, "certificate request scope mismatch", http.StatusBadRequest)
			return
		}
		publicKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(input.PublicKeyString))
		if err != nil || len(bytes.TrimSpace(rest)) != 0 {
			http.Error(writer, "invalid public key", http.StatusBadRequest)
			return
		}
		certificate := &ssh.Certificate{
			Key: publicKey, CertType: ssh.UserCert, ValidPrincipals: []string{"alice"},
			ValidAfter:  uint64(time.Now().Add(-time.Second).Unix()),
			ValidBefore: uint64(time.Now().Add(time.Minute).Unix()),
		}
		if err := certificate.SignCert(rand.Reader, caSigner); err != nil {
			http.Error(writer, "failed to sign certificate", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(writer).Encode(&client.SshCertResponse{
			Certificate: string(ssh.MarshalAuthorizedKey(certificate)),
			Hostkeys:    []string{hostkey},
		})
	}))
	defer api.Close()

	executable := filepath.Join(t.TempDir(), "filezilla")
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--version\" ]; then printf 'FileZilla 3.71.1\\n'; exit 0; fi\n" +
		"export FLOTTE_FILEZILLA_HELPER=1 FILEZILLA_SITE=\"$1\"\n" +
		"exec " + shellQuote(testBinary) + " -test.run='^TestFileZillaAgentHelper$'\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	var output, errorsOutput bytes.Buffer
	t.Setenv("SSH_AUTH_SOCK", "/tmp/preexisting-agent.sock")
	err = Run(context.Background(), Options{
		Executable: executable,
		ServerURL:  api.URL,
		Token:      "test-token",
		Site:       Site{Host: "127.0.0.1", Port: port, User: "alice"},
		Output:     &output,
		Errors:     &errorsOutput,
	})
	if err != nil {
		t.Fatalf("FileZilla integration failed: %v; stderr=%s", err, errorsOutput.String())
	}
	if !strings.Contains(output.String(), "temporary FileZilla profile") {
		t.Fatalf("missing temporary-profile message: %s", output.String())
	}
}

func TestFileZillaAgentHelper(t *testing.T) {
	if os.Getenv("FLOTTE_FILEZILLA_HELPER") != "1" {
		return
	}
	if os.Getenv("FILEZILLA_SITE") != "--site=0/Flotte/session" {
		t.Fatal("FileZilla was not started with the temporary Flotte site")
	}
	profileDir := os.Getenv("FLOTTE_FILEZILLA_CONFIG")
	for _, file := range []string{"sitemanager.xml", "hostkeys.xml"} {
		if _, err := os.Stat(filepath.Join(profileDir, file)); err != nil {
			t.Fatalf("missing temporary FileZilla profile %s: %v", file, err)
		}
	}
	connection, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		t.Fatalf("dial Flotte agent: %v", err)
	}
	defer connection.Close()
	client := agent.NewClient(connection)
	keys, err := client.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("agent identities = %d, err=%v", len(keys), err)
	}
	publicKey, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	certificate, ok := publicKey.(*ssh.Certificate)
	if !ok || keys[0].Format != certificate.Type() || len(certificate.ValidPrincipals) != 1 || certificate.ValidPrincipals[0] != "alice" {
		t.Fatal("agent did not offer an Alice user certificate")
	}
	payload := []byte("FileZilla agent signature")
	signature, err := client.Sign(certificate, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate.Key.Verify(payload, signature); err != nil {
		t.Fatalf("agent signature invalid: %v", err)
	}
}

func testSigner(t *testing.T, seed byte) ssh.Signer {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
