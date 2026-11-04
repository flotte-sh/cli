package config

import "testing"

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
			endpoint: "/auth/cli/device/start",
			want:     "https://example.com/flotte/auth/cli/device/start",
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
