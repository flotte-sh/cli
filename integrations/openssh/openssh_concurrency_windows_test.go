package openssh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestWindowsConcurrentAgentRefresh(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	private, err := LoadCLIPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "flotte agent.exe")
	if output, err := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "../../cmd/flotte").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	makeCredential := func() ([]byte, *ssh.Certificate) {
		signer, err := ssh.NewSignerFromKey(private)
		if err != nil {
			t.Fatal(err)
		}
		certificate := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
		if err := certificate.SignCert(rand.Reader, signer); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(Credential{Certificate: string(ssh.MarshalAuthorizedKey(certificate))})
		if err != nil {
			t.Fatal(err)
		}
		return data, certificate
	}
	data, certificate := makeCredential()
	var nonce [20]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	hash := hex.EncodeToString(nonce[:])
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	first := exec.CommandContext(ctx, binary, "ssh-agent-serve", hash)
	first.Stdin = bytes.NewReader(data)
	ready, err := first.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Process.Kill(); _ = first.Wait() }()
	if line, err := bufio.NewReader(ready).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("ready=%q err=%v", line, err)
	}
	prefix, err := agentEndpointPrefix()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := winio.DialPipeContext(ctx, agentEndpointPath(prefix, hash))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
	client := agent.NewClient(connection)
	keys, err := client.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	replacement, _ := makeCredential()
	var requests sync.WaitGroup
	for range 8 {
		requests.Go(func() {
			command := exec.CommandContext(ctx, binary, "ssh-agent-serve", hash)
			command.Stdin = bytes.NewReader(replacement)
			output, err := command.Output()
			if err != nil || string(output) != "ready\n" {
				t.Errorf("provision: %v output=%q", err, output)
			}
		})
	}
	requests.Wait()
	payload := []byte("concurrent agent signing")
	signature, err := client.Sign(certificate, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate.Verify(payload, signature); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveAll(); err == nil {
		t.Fatal("public agent accepted mutation")
	}
}
