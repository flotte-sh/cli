//go:build windows

package winscp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/flotte-sh/flotte-cli/integrations/internal/pageant"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

func TestPageantExclusiveAgentAndRestart(t *testing.T) {
	name := `\\.\pipe\flotte-pageant-test-` + rand.Text()
	listener, err := pageant.ListenPipe(name)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	duplicate, err := pageant.ListenPipe(name)
	if err == nil {
		duplicate.Close()
		t.Fatal("a second Pageant listener took over the endpoint")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &ssh.Certificate{
		Key: key, CertType: ssh.UserCert, KeyId: "Flotte Pageant transport test",
		ValidPrincipals: []string{"test-user"}, ValidBefore: ssh.CertTimeInfinity,
	}
	if err := certificate.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: private, Certificate: certificate}); err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serveDone <- err
			return
		}
		defer connection.Close()
		serveDone <- agent.ServeAgent(keyring, connection)
	}()
	timeout := 5 * time.Second
	connection, err := winio.DialPipe(name, &timeout)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(connection)
	identities, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 || !bytes.Equal(identities[0].Blob, certificate.Marshal()) {
		t.Fatalf("listener did not serve the expected certificate: %v", identities)
	}
	message := []byte("authenticate only using the endpoint we created")
	signature, err := client.Sign(certificate, message)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Verify(message, signature); err != nil {
		t.Fatalf("agent signature does not match its certificate: %v", err)
	}
	connection.Close()
	select {
	case err := <-serveDone:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	case <-time.After(timeout):
		t.Fatal("agent did not finish after the client disconnected")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := pageant.ListenPipe(name)
	if err != nil {
		t.Fatalf("closed Pageant endpoint was not released: %v", err)
	}
	defer restarted.Close()
}

func pageantTestConnection(t *testing.T) (net.Conn, string) {
	t.Helper()
	name := `\\.\pipe\flotte-pageant-test-` + rand.Text()
	listener, err := pageant.ListenPipe(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	accepted := make(chan net.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptErrors <- err
			return
		}
		accepted <- connection
	}()
	timeout := 5 * time.Second
	client, err := winio.DialPipe(name, &timeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	select {
	case server := <-accepted:
		t.Cleanup(func() { server.Close() })
		return server, name
	case err := <-acceptErrors:
		t.Fatal(err)
	case <-time.After(timeout):
		t.Fatal("listener did not accept the pipe connection")
	}
	return nil, ""
}

func TestPageantPipeCurrentUserSecurity(t *testing.T) {
	connection, _ := pageantTestConnection(t)
	file, ok := connection.(interface{ Fd() uintptr })
	if !ok {
		t.Fatal("pipe connection does not expose its Windows handle")
	}
	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Equals(user.User.Sid) {
		t.Fatalf("pipe owner %s is not the current process user %s", owner, user.User.Sid)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("pipe DACL permits inherited access")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("expected exactly one explicit owner-only ACE, got %v", dacl)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
		t.Fatalf("unexpected owner ACE header: %+v", ace.Header)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.Equals(user.User.Sid) {
		t.Fatalf("pipe grants access to %s instead of only %s", aceSID, user.User.Sid)
	}
	if ace.Mask&windows.GENERIC_ALL == 0 && uint32(ace.Mask)&0x1f01ff != 0x1f01ff {
		t.Fatalf("owner does not have full pipe access: %#x", ace.Mask)
	}
}

func TestPageantPipeRejectsNetworkClients(t *testing.T) {
	if windows.NewLazySystemDLL("ntdll.dll").NewProc("wine_get_version").Find() == nil {
		t.Skip("Wine does not implement native SMB named pipe access controls")
	}
	name := `\\.\pipe\flotte-pageant-test-` + rand.Text()
	listener, err := pageant.ListenPipe(name)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			connection.Close()
		}
	}()
	remote, err := windows.UTF16PtrFromString(`\\localhost\pipe\` + strings.TrimPrefix(name, `\\.\pipe\`))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(remote, windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING, 0, 0)
	if err == nil {
		windows.CloseHandle(handle)
		t.Fatal("Pageant pipe accepted a network connection")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skipf("local SMB transport is unavailable or cannot exercise remote rejection: %v", err)
	}
}
