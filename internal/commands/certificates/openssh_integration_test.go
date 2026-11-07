package certificates

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flotte-sh/cli/internal/auth"
	"github.com/flotte-sh/cli/internal/client"
	"github.com/flotte-sh/cli/internal/config"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

func TestNativeOpenSSHIntegration(t *testing.T) {
	if os.Getenv("FLOTTE_TEST_OPENSSH") != "1" {
		t.Skip("set FLOTTE_TEST_OPENSSH=1 for real OpenSSH integration")
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH unavailable")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	privateKeyPath, err := config.GetActiveSSHPrivateKeyPath()
	if err != nil {
		t.Fatal(err)
	}
	privateKeyBefore, err := os.ReadFile(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPath, err := config.GetActiveSSHPubKeyPath()
	if err != nil {
		t.Fatal(err)
	}
	publicKeyBefore, err := os.ReadFile(publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for path, expected := range map[string][]byte{privateKeyPath: privateKeyBefore, publicKeyPath: publicKeyBefore} {
			actual, err := os.ReadFile(path)
			if err != nil {
				t.Error(err)
			} else if !bytes.Equal(actual, expected) {
				t.Errorf("CLI key file changed: %s", path)
			}
		}
	})
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverConfig := &ssh.ServerConfig{PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		certificate, ok := key.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("certificate required")
		}
		checker := &ssh.CertChecker{IsUserAuthority: func(authority ssh.PublicKey) bool {
			return bytes.Equal(authority.Marshal(), signer.PublicKey().Marshal())
		}}
		if err := checker.CheckCert(metadata.User(), certificate); err != nil {
			return nil, err
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)
	remoteAddresses := make(chan string, 1)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				server, channels, requests, err := ssh.NewServerConn(connection, serverConfig)
				if err != nil {
					return
				}
				defer server.Close()
				go serveNativeForwardRequests(server, requests, remoteAddresses)
				for incoming := range channels {
					if incoming.ChannelType() == "direct-tcpip" {
						go serveNativeDirectForward(incoming)
						continue
					}
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					channel, channelRequests, err := incoming.Accept()
					if err != nil {
						return
					}
					for request := range channelRequests {
						if request.Type == "exec" {
							_ = request.Reply(true, nil)
							_, _ = io.WriteString(channel, server.User()+"\n")
							_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							_ = channel.Close()
							break
						}
						_ = request.Reply(false, nil)
					}
				}
			}()
		}
	}()
	var rejectHost atomic.Bool
	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/auth/me" {
			_ = json.NewEncoder(writer).Encode(client.UserInfoResponse{Authenticated: true})
			return
		}
		if request.URL.Path != "/ssh/cert" {
			http.NotFound(writer, request)
			return
		}
		var input client.SshCertRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			http.Error(writer, "bad request", 400)
			return
		}
		if input.PublicKeyString != string(publicKeyBefore) {
			t.Errorf("certificate request for %s did not reuse the existing CLI public key", input.ServerUser)
			http.Error(writer, "unexpected key", http.StatusBadRequest)
			return
		}
		if rejectHost.Load() || input.ServerHostkey != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) {
			http.Error(writer, "unknown host", http.StatusForbidden)
			return
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(input.PublicKeyString))
		if err != nil {
			http.Error(writer, "invalid key", 400)
			return
		}
		certificate := &ssh.Certificate{Key: key, CertType: ssh.UserCert, ValidPrincipals: []string{input.ServerUser}, ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Minute).Unix())}
		if err := certificate.SignCert(rand.Reader, signer); err != nil {
			http.Error(writer, "signing failed", 500)
			return
		}
		_ = json.NewEncoder(writer).Encode(client.SshCertResponse{Certificate: string(ssh.MarshalAuthorizedKey(certificate)), Hostkeys: []string{string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}})
	}))
	defer api.Close()
	if err := (&config.ClientConfig{FlotteUrl: api.URL}).Save(); err != nil {
		t.Fatal(err)
	}
	keyring.MockInitWithError(errors.New("integration uses isolated file storage"))
	if err := auth.SaveToken("integration-only"); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "flotte app's")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	// go test runs with the package directory (cli/internal/commands/certificates) as the working directory
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "../../../cmd/flotte")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	install := exec.CommandContext(t.Context(), binary, "ssh-config", "install")
	if output, err := install.CombinedOutput(); err != nil {
		t.Fatalf("install: %v\n%s", err, output)
	}
	configPath := filepath.Join(home, ".ssh", "config")
	file, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	_, err = fmt.Fprintf(file, "Host native-alias native-jump native-jump2\n HostName 127.0.0.1\n Port %s\n BatchMode yes\n IdentityFile none\n ForwardAgent no\nHost native-jump\n User jumper\nHost native-jump2\n User jumper2\n", port)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	var concurrent sync.WaitGroup
	for _, user := range []string{"alice", "bob", "carol", "dave", "alice", "alice", "alice", "alice"} {
		concurrent.Go(func() {
			command := exec.CommandContext(t.Context(), "ssh", "-vvv", "-F", configPath, user+"@native-alias", "whoami")
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			if err := command.Run(); err != nil {
				t.Errorf("%s: %v\n%s", user, err, stderr.String())
				return
			}
			if stdout.String() != user+"\n" {
				t.Errorf("wrong identity: %q", stdout.String())
			}
			trace := stderr.String()
			hostkeys := strings.Index(trace, "KnownHostsCommand-HOSTNAME")
			identities := strings.Index(trace, "agent returned 1 keys")
			if hostkeys < 0 || identities < hostkeys {
				t.Errorf("host-key provisioning did not precede agent listing:\n%s", trace)
			}
			t.Logf("%s: alias resolved; helper ran before agent listing; exactly one certificate authenticated", user)
		})
	}
	concurrent.Wait()
	t.Run("ResolvedAliasWithIdentityAgentNone", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "ssh", "-F", configPath, "alice@native-alias", "whoami")
		output, err := command.CombinedOutput()
		if err != nil || string(output) != "alice\n" {
			t.Fatalf("resolved file identity: %v, output=%q", err, output)
		}
	})
	t.Run("MultipleProxyJumps", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "ssh", "-F", configPath, "-J", "native-jump,native-jump2", "alice@native-alias", "whoami")
		output, err := command.CombinedOutput()
		if err != nil || string(output) != "alice\n" {
			t.Fatalf("multiple jumps: %v, output=%q", err, output)
		}
	})
	t.Run("ProxyJump", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "ssh", "-F", configPath, "-J", "native-jump", "alice@native-alias", "whoami")
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil || stdout.String() != "alice\n" {
			t.Fatalf("jump: %v, stdout=%q\n%s", err, stdout.String(), stderr.String())
		}
	})
	for _, direction := range []string{"local", "remote"} {
		t.Run(direction+" forwarding", func(t *testing.T) {
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				for {
					connection, err := echo.Accept()
					if err != nil {
						return
					}
					go func() {
						defer connection.Close()
						_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
						_, _ = io.Copy(connection, connection)
					}()
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			address := "127.0.0.1:0"
			flag := "-R"
			if direction == "local" {
				reservation, err := net.Listen("tcp", address)
				if err != nil {
					t.Fatal(err)
				}
				address = reservation.Addr().String()
				_ = reservation.Close()
				flag = "-L"
			}
			command := exec.CommandContext(ctx, "ssh", "-F", configPath, "-o", "ExitOnForwardFailure=yes", "-N", flag, address+":"+echo.Addr().String(), "alice@native-alias")
			var stderr bytes.Buffer
			command.Stderr = &stderr
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				cancel()
				_ = command.Wait()
				if t.Failed() {
					t.Log(stderr.String())
				}
			}()
			if direction == "remote" {
				select {
				case address = <-remoteAddresses:
				case <-ctx.Done():
					t.Fatal("remote forward was not established")
				}
			}
			var connection net.Conn
			for {
				connection, err = net.DialTimeout("tcp", address, time.Second)
				if err == nil {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal(err)
				case <-time.After(20 * time.Millisecond):
				}
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte("native-forward\x00\xff"), 4096)
			if _, err := connection.Write(payload); err != nil {
				t.Fatal(err)
			}
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(connection, received); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("forwarded payload changed")
			}
		})
	}
	rejectHost.Store(true)
	denied := exec.CommandContext(t.Context(), "ssh", "-F", configPath, "alice@native-alias", "whoami")
	if output, err := denied.CombinedOutput(); err == nil {
		t.Fatalf("unapproved host authenticated: %s", output)
	}
}

type nativeForwardAddress struct {
	Host string
	Port uint32
}

type nativeForwardChannel struct {
	DestinationHost string
	DestinationPort uint32
	OriginHost      string
	OriginPort      uint32
}

type nativeDirectChannel struct {
	Host       string
	Port       uint32
	Origin     string
	OriginPort uint32
}

func bridgeNativeForward(channel ssh.Channel, connection net.Conn) {
	defer channel.Close()
	defer connection.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(channel, connection)
		_ = channel.CloseWrite()
		close(done)
	}()
	_, _ = io.Copy(connection, channel)
	_ = connection.(*net.TCPConn).CloseWrite()
	<-done
}

func serveNativeDirectForward(incoming ssh.NewChannel) {
	var address nativeDirectChannel
	if err := ssh.Unmarshal(incoming.ExtraData(), &address); err != nil || address.Host != "127.0.0.1" {
		_ = incoming.Reject(ssh.Prohibited, "loopback only")
		return
	}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(address.Host, fmt.Sprint(address.Port)), 5*time.Second)
	if err != nil {
		_ = incoming.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	channel, requests, err := incoming.Accept()
	if err != nil {
		_ = connection.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	bridgeNativeForward(channel, connection)
}

func serveNativeForwardRequests(server *ssh.ServerConn, requests <-chan *ssh.Request, addresses chan<- string) {
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for request := range requests {
		var address nativeForwardAddress
		if request.Type != "tcpip-forward" || ssh.Unmarshal(request.Payload, &address) != nil || address.Host != "127.0.0.1" || address.Port != 0 {
			_ = request.Reply(false, nil)
			continue
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			_ = request.Reply(false, nil)
			continue
		}
		listeners = append(listeners, listener)
		address.Port = uint32(listener.Addr().(*net.TCPAddr).Port)
		_ = request.Reply(true, ssh.Marshal(struct{ Port uint32 }{address.Port}))
		addresses <- listener.Addr().String()
		go func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					origin := connection.RemoteAddr().(*net.TCPAddr)
					channel, channelRequests, err := server.OpenChannel("forwarded-tcpip", ssh.Marshal(nativeForwardChannel{DestinationHost: address.Host, DestinationPort: address.Port, OriginHost: origin.IP.String(), OriginPort: uint32(origin.Port)}))
					if err != nil {
						_ = connection.Close()
						return
					}
					go ssh.DiscardRequests(channelRequests)
					bridgeNativeForward(channel, connection)
				}()
			}
		}()
	}
}
