package openssh

import (
	"os"
	"testing"
)

func TestParseSSHCommand(t *testing.T) {
	// Save original env vars and restore after tests
	originalUser := os.Getenv("USER")
	originalUsername := os.Getenv("USERNAME")
	defer func() {
		os.Setenv("USER", originalUser)
		os.Setenv("USERNAME", originalUsername)
	}()

	// Set a default user for tests that don't specify one
	os.Setenv("USER", "testuser")
	os.Setenv("USERNAME", "testuser")

	tests := []struct {
		name        string
		args        []string
		wantUser    string
		wantHost    string
		wantPort    string
		wantErr     bool
		envUser     string // override USER env var for this test
		envUsername string // override USERNAME env var for this test
	}{
		// Basic formats
		{
			name:     "simple user@host",
			args:     []string{"admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "host only with env user",
			args:     []string{"server.example.com"},
			wantUser: "testuser",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "host with ip address",
			args:     []string{"root@192.168.1.100"},
			wantUser: "root",
			wantHost: "192.168.1.100",
			wantPort: "22",
		},
		{
			name:     "host with ipv6 address",
			args:     []string{"user@::1"},
			wantUser: "user",
			wantHost: "::1",
			wantPort: "22",
		},

		// ssh:// URL format
		{
			name:     "ssh:// URL with user host and port",
			args:     []string{"ssh://admin@server.example.com:2222"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "2222",
		},
		{
			name:     "ssh:// URL with user and host only",
			args:     []string{"ssh://admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "ssh:// URL with host and port only",
			args:     []string{"ssh://server.example.com:2222"},
			wantUser: "testuser",
			wantHost: "server.example.com",
			wantPort: "2222",
		},
		{
			name:     "ssh:// URL with host only",
			args:     []string{"ssh://server.example.com"},
			wantUser: "testuser",
			wantHost: "server.example.com",
			wantPort: "22",
		},

		// -l user flag
		{
			name:     "-l flag for user",
			args:     []string{"-l", "admin", "server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "-l flag with user@host (-l takes precedence as it's parsed first)",
			args:     []string{"-l", "override", "admin@server.example.com"},
			wantUser: "override", // -l is parsed before host, so it takes precedence
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "-l flag after host still sets user",
			args:     []string{"server.example.com", "-l", "admin"},
			wantUser: "admin", // user from host is empty, -l still applies
			wantHost: "server.example.com",
			wantPort: "22",
		},

		// -p port flag
		{
			name:     "-p flag for port",
			args:     []string{"-p", "2222", "admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "2222",
		},
		{
			name:     "-p flag with ssh:// URL port (flag takes precedence)",
			args:     []string{"-p", "3333", "ssh://admin@server.example.com:2222"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "3333",
		},
		{
			name:     "-p flag after host still sets port",
			args:     []string{"admin@server.example.com", "-p", "2222"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "2222", // -p after host still works since port wasn't set
		},

		// Combined -l and -p flags
		{
			name:     "-l and -p flags together",
			args:     []string{"-l", "admin", "-p", "2222", "server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "2222",
		},
		{
			name:     "-p and -l flags reversed",
			args:     []string{"-p", "2222", "-l", "admin", "server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "2222",
		},

		// Flags without arguments (from sshFlagsNoArgs: "46AaCfGgKkMNnqsTtVvXxYy")
		{
			name:     "-v verbose flag before host",
			args:     []string{"-v", "admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "-4 IPv4 flag before host",
			args:     []string{"-4", "admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "-6 IPv6 flag before host",
			args:     []string{"-6", "admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "multiple no-arg flags before host",
			args:     []string{"-v", "-v", "-A", "admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "combined no-arg flags",
			args:     []string{"-vvA", "admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},

		// Other flags with arguments (like -o, -i, -L, etc.)
		{
			name:     "-o option flag",
			args:     []string{"-o", "StrictHostKeyChecking=no", "admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "-i identity flag",
			args:     []string{"-i", "/path/to/key", "admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "-L local forward flag",
			args:     []string{"-L", "8080:localhost:80", "admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "-R remote forward flag",
			args:     []string{"-R", "8080:localhost:80", "admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "-D dynamic port forwarding",
			args:     []string{"-D", "1080", "admin@server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},

		// Commands after destination
		{
			name:     "command after host",
			args:     []string{"admin@server.example.com", "ls", "-la"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "command with flags after host",
			args:     []string{"admin@server.example.com", "cat", "/etc/passwd"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "-- separator before command",
			args:     []string{"admin@server.example.com", "--", "ls", "-la"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},

		// Complex combinations
		{
			name:     "all flags combined",
			args:     []string{"-v", "-p", "2222", "-l", "admin", "-o", "StrictHostKeyChecking=no", "server.example.com"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "2222",
		},
		{
			name:     "flags and command",
			args:     []string{"-v", "-p", "2222", "admin@server.example.com", "uptime"},
			wantUser: "admin",
			wantHost: "server.example.com",
			wantPort: "2222",
		},

		// Error cases
		{
			name:    "empty args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "only flags no host",
			args:    []string{"-v", "-p", "2222"},
			wantErr: true,
		},
		{
			name:        "no user available",
			args:        []string{"server.example.com"},
			wantErr:     true,
			envUser:     "",
			envUsername: "",
		},

		// Edge cases
		{
			name:     "host with subdomain",
			args:     []string{"admin@sub.domain.example.com"},
			wantUser: "admin",
			wantHost: "sub.domain.example.com",
			wantPort: "22",
		},
		{
			name:     "host with hyphen",
			args:     []string{"admin@my-server.example.com"},
			wantUser: "admin",
			wantHost: "my-server.example.com",
			wantPort: "22",
		},
		{
			name:     "user with hyphen",
			args:     []string{"my-admin@server.example.com"},
			wantUser: "my-admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "user with underscore",
			args:     []string{"my_admin@server.example.com"},
			wantUser: "my_admin",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "user with dots",
			args:     []string{"first.last@server.example.com"},
			wantUser: "first.last",
			wantHost: "server.example.com",
			wantPort: "22",
		},
		{
			name:     "localhost",
			args:     []string{"admin@localhost"},
			wantUser: "admin",
			wantHost: "localhost",
			wantPort: "22",
		},
		{
			name:     "short hostname",
			args:     []string{"admin@myhost"},
			wantUser: "admin",
			wantHost: "myhost",
			wantPort: "22",
		},
		{
			name:     "command after short hostname",
			args:     []string{"admin@myhost", "/bin/mkdir", "/testdir"},
			wantUser: "admin",
			wantHost: "myhost",
			wantPort: "22",
		},
		{
			name:     "command has -p flag",
			args:     []string{"admin@myhost", "/bin/mkdir", "-p", "/testdir/touch"},
			wantUser: "admin",
			wantHost: "myhost",
			wantPort: "22",
		},
		{
			name:     "user with hyphen",
			args:     []string{"admin-peter@myhost"},
			wantUser: "admin-peter",
			wantHost: "myhost",
			wantPort: "22",
		},

		// USERNAME fallback when USER is empty
		{
			name:        "USERNAME env fallback",
			args:        []string{"server.example.com"},
			wantUser:    "windowsuser",
			wantHost:    "server.example.com",
			wantPort:    "22",
			envUser:     "",
			envUsername: "windowsuser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment for this test
			if tt.envUser != "" || tt.envUsername != "" || (tt.envUser == "" && tt.name == "no user available") || (tt.envUser == "" && tt.name == "USERNAME env fallback") {
				os.Setenv("USER", tt.envUser)
				os.Setenv("USERNAME", tt.envUsername)
			} else {
				os.Setenv("USER", "testuser")
				os.Setenv("USERNAME", "testuser")
			}

			gotUser, gotHost, gotPort, err := parseSSHCommand(tt.args)

			if tt.wantErr {
				if err == nil {
					t.Error("parseSshCommand() expected error, got nil")
					return
				}
				return
			}

			if err != nil {
				t.Errorf("parseSshCommand() unexpected error = %v", err)
				return
			}

			if gotUser != tt.wantUser {
				t.Errorf("parseSshCommand() user = %q, want %q", gotUser, tt.wantUser)
			}
			if gotHost != tt.wantHost {
				t.Errorf("parseSshCommand() host = %q, want %q", gotHost, tt.wantHost)
			}
			if gotPort != tt.wantPort {
				t.Errorf("parseSshCommand() port = %q, want %q", gotPort, tt.wantPort)
			}
		})
	}
}

func TestParseSSHCommandFlagOrder(t *testing.T) {
	os.Setenv("USER", "testuser")
	os.Setenv("USERNAME", "testuser")

	tests := []struct {
		name     string
		args     []string
		wantUser string
		wantHost string
		wantPort string
	}{
		{
			name:     "-l flag is parsed first so takes precedence over user in URL",
			args:     []string{"-l", "flaguser", "urluser@host.com"},
			wantUser: "flaguser", // -l is parsed before host, so it wins
			wantHost: "host.com",
			wantPort: "22",
		},
		{
			name:     "port in -p takes precedence over URL port",
			args:     []string{"-p", "1111", "ssh://user@host.com:2222"},
			wantUser: "user",
			wantHost: "host.com",
			wantPort: "1111",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUser, gotHost, gotPort, err := parseSSHCommand(tt.args)
			if err != nil {
				t.Errorf("parseSshCommand() unexpected error = %v", err)
				return
			}
			if gotUser != tt.wantUser {
				t.Errorf("parseSshCommand() user = %q, want %q", gotUser, tt.wantUser)
			}
			if gotHost != tt.wantHost {
				t.Errorf("parseSshCommand() host = %q, want %q", gotHost, tt.wantHost)
			}
			if gotPort != tt.wantPort {
				t.Errorf("parseSshCommand() port = %q, want %q", gotPort, tt.wantPort)
			}
		})
	}
}

func TestParseSSHCommandDoubleHyphen(t *testing.T) {
	os.Setenv("USER", "testuser")
	os.Setenv("USERNAME", "testuser")

	tests := []struct {
		name     string
		args     []string
		wantUser string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{
			name:    "-- before host should stop parsing",
			args:    []string{"--", "admin@host.com"},
			wantErr: true, // host won't be found because -- stops parsing
		},
		{
			name:     "host then -- then command args",
			args:     []string{"admin@host.com", "--", "-v", "-p", "2222"},
			wantUser: "admin",
			wantHost: "host.com",
			wantPort: "22", // -p after -- is part of command, not ssh flag
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUser, gotHost, gotPort, err := parseSSHCommand(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseSshCommand() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("parseSshCommand() unexpected error = %v", err)
				return
			}
			if gotUser != tt.wantUser {
				t.Errorf("parseSshCommand() user = %q, want %q", gotUser, tt.wantUser)
			}
			if gotHost != tt.wantHost {
				t.Errorf("parseSshCommand() host = %q, want %q", gotHost, tt.wantHost)
			}
			if gotPort != tt.wantPort {
				t.Errorf("parseSshCommand() port = %q, want %q", gotPort, tt.wantPort)
			}
		})
	}
}
