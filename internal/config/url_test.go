package config

import (
	"errors"
	"testing"
)

func TestNormalizeFlotteURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "adds https scheme", raw: "flotte.example.com", want: "https://flotte.example.com"},
		{name: "trims trailing slash", raw: "http://localhost:3001/", want: "http://localhost:3001"},
		{name: "keeps base path", raw: "https://example.com/flotte/", want: "https://example.com/flotte"},
		{name: "rejects query", raw: "https://example.com/flotte?x=1", wantErr: true},
		{name: "rejects fragment", raw: "https://example.com/flotte#x", wantErr: true},
		{name: "rejects userinfo", raw: "https://user@example.com", wantErr: true},
		{name: "rejects malformed scheme prefix", raw: "://bad", wantErr: true},
		{name: "rejects port without hostname", raw: "https://:443", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeFlotteURL(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeFlotteURL(%q) expected error", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeFlotteURL(%q) unexpected error: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeFlotteURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestJoinEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		endpoint string
		want     string
	}{
		{
			name:     "root deployment",
			baseURL:  "http://localhost:3001",
			endpoint: "/auth/me",
			want:     "http://localhost:3001/auth/me",
		},
		{
			name:     "base path deployment",
			baseURL:  "https://example.com/flotte/",
			endpoint: "/auth/cli/token",
			want:     "https://example.com/flotte/auth/cli/token",
		},
		{
			name:     "endpoint without leading slash",
			baseURL:  "https://example.com/flotte",
			endpoint: "ssh/cert",
			want:     "https://example.com/flotte/ssh/cert",
		},
		{
			name:     "path escaping",
			baseURL:  "https://example.com/flotte dev",
			endpoint: "/.well-known/cli-config",
			want:     "https://example.com/flotte%20dev/.well-known/cli-config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JoinEndpoint(tt.baseURL, tt.endpoint)
			if err != nil {
				t.Fatalf("JoinEndpoint(%q, %q) unexpected error: %v", tt.baseURL, tt.endpoint, err)
			}
			if got != tt.want {
				t.Fatalf("JoinEndpoint(%q, %q) = %q, want %q", tt.baseURL, tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestNormalizeFlotteURLSchemeCase(t *testing.T) {
	got, err := NormalizeFlotteURL("HTTPS://flotte.example/base/")
	if err != nil || got != "https://flotte.example/base" {
		t.Fatalf("NormalizeFlotteURL = %q, %v", got, err)
	}
	for _, raw := range []string{"file:///etc/passwd", "ftp://flotte.example", "javascript://flotte.example"} {
		if got, err := NormalizeFlotteURL(raw); err == nil {
			t.Errorf("NormalizeFlotteURL(%q) = %q, want an error", raw, got)
		}
	}
}

func TestReportedServerURL(t *testing.T) {
	for _, test := range []struct {
		name     string
		entered  string
		reported string
		want     string
	}{
		{name: "same address", entered: "https://flotte.example.com", reported: "https://flotte.example.com/", want: "https://flotte.example.com"},
		{name: "base path on the same host", entered: "https://example.com/flotte/login", reported: "https://example.com/flotte", want: "https://example.com/flotte"},
		{name: "upgrade to https on the same host", entered: "http://flotte.example.com", reported: "https://flotte.example.com", want: "https://flotte.example.com"},
		{name: "host in another case", entered: "https://Flotte.Example.com", reported: "https://flotte.example.com", want: "https://flotte.example.com"},
		{name: "another host", entered: "https://flotte.example.com", reported: "https://attacker.example"},
		{name: "host that only starts the same", entered: "https://flotte.example.com", reported: "https://flotte.example.com.attacker.example"},
		{name: "another port", entered: "https://flotte.example.com", reported: "https://flotte.example.com:8443"},
		{name: "downgrade to http", entered: "https://flotte.example.com", reported: "http://flotte.example.com"},
		{name: "host hidden in the scheme", entered: "http://localhost:3001", reported: "https://attacker.example/a://localhost:3001"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ReportedServerURL(test.entered, test.reported)
			if test.want == "" {
				var otherServer *OtherServerError
				if !errors.As(err, &otherServer) || got != "" {
					t.Fatalf("ReportedServerURL(%q, %q) = %q, %v; want it refused as another server", test.entered, test.reported, got, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("ReportedServerURL(%q, %q) = %q, %v; want %q", test.entered, test.reported, got, err, test.want)
			}
		})
	}
	if _, err := ReportedServerURL("https://flotte.example.com", "ftp://flotte.example.com"); err == nil {
		t.Fatal("an address with an unsupported scheme was accepted")
	}
}
