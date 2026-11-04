package certificates

import (
	common "github.com/flotte-sh/flotte-cli/internal/commands/common"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSSHTarget(t *testing.T) {
	tests := []struct {
		name              string
		target            string
		wantUser          string
		wantServerAddress string
		wantErr           bool
		errContains       string
	}{
		{
			name:              "user and host with explicit port",
			target:            "test@host.docker.internal:2221",
			wantUser:          "test",
			wantServerAddress: "host.docker.internal:2221",
		},
		{
			name:              "user and host without port defaults to 22",
			target:            "root@myserver.example.com",
			wantUser:          "root",
			wantServerAddress: "myserver.example.com:22",
		},
		{
			name:              "ip address with port",
			target:            "admin@192.168.1.100:2222",
			wantUser:          "admin",
			wantServerAddress: "192.168.1.100:2222",
		},
		{
			name:              "ip address without port defaults to 22",
			target:            "admin@192.168.1.100",
			wantUser:          "admin",
			wantServerAddress: "192.168.1.100:22",
		},
		{
			name:        "missing @ separator",
			target:      "host.docker.internal:2221",
			wantErr:     true,
			errContains: "invalid format",
		},
		{
			name:        "empty username",
			target:      "@host.docker.internal:2221",
			wantErr:     true,
			errContains: "username is required",
		},
		{
			name:        "empty server address",
			target:      "test@",
			wantErr:     true,
			errContains: "server address is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, serverAddress, err := common.ParseSSHTarget(tt.target)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSSHTarget(%q) expected error, got nil", tt.target)
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("parseSSHTarget(%q) error = %q, want it to contain %q", tt.target, err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseSSHTarget(%q) unexpected error: %v", tt.target, err)
			}
			if user != tt.wantUser {
				t.Errorf("parseSSHTarget(%q) user = %q, want %q", tt.target, user, tt.wantUser)
			}
			if serverAddress != tt.wantServerAddress {
				t.Errorf("parseSSHTarget(%q) serverAddress = %q, want %q", tt.target, serverAddress, tt.wantServerAddress)
			}
		})
	}
}

func TestResolvePublicKey(t *testing.T) {
	dir := t.TempDir()
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	writeKeyFile := func(relPath, content string) {
		abs := filepath.Join(dir, relPath)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeKeyFile("id_ed25519.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/file/key\n")
	writeKeyFile("id_rsa.pub", "ssh-rsa AAAAB3NzaC1yc2E/from/file\n")
	writeKeyFile("trailing newline.pub", "ssh-ed25519 AAAAtrailing/newline\n\n\n")
	writeKeyFile("empty.pub", "")

	tests := []struct {
		name    string
		arg     string
		want    string
		wantErr bool
	}{
		{
			name: "raw public key string passed through",
			arg:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIraw/key",
			want: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIraw/key",
		},
		{
			name: "file path reads key content and trims newlines",
			arg:  filepath.Join(dir, "id_ed25519.pub"),
			want: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/file/key",
		},
		{
			name: "relative file path reads key content",
			arg:  "./id_ed25519.pub",
			want: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/file/key",
		},
		{
			name: "rsa key from file",
			arg:  filepath.Join(dir, "id_rsa.pub"),
			want: "ssh-rsa AAAAB3NzaC1yc2E/from/file",
		},
		{
			name: "trailing newlines are stripped",
			arg:  filepath.Join(dir, "trailing newline.pub"),
			want: "ssh-ed25519 AAAAtrailing/newline",
		},
		{
			name: "empty file yields empty string with no error",
			arg:  filepath.Join(dir, "empty.pub"),
			want: "",
		},
		{
			name:    "nonexistent file treated as raw key (no read attempt)",
			arg:     "ecdsa-sha2-nistp256 AAAAlooks/like/key/but/no/file",
			want:    "ecdsa-sha2-nistp256 AAAAlooks/like/key/but/no/file",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := common.ResolvePublicKey(tt.arg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolvePublicKey(%q) expected error, got nil", tt.arg)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePublicKey(%q) unexpected error: %v", tt.arg, err)
			}
			if got != tt.want {
				t.Errorf("resolvePublicKey(%q) = %q, want %q", tt.arg, got, tt.want)
			}
		})
	}
}
