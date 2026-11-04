package config

import "testing"

func TestValidateOIDCEndpointURL(t *testing.T) {
	tests := []struct {
		name      string
		rawURL    string
		wantURL   string
		wantError bool
	}{
		{name: "empty allowed", rawURL: "", wantURL: ""},
		{name: "https endpoint", rawURL: "https://login.example.com/oauth2/v2.0/authorize?p=policy", wantURL: "https://login.example.com/oauth2/v2.0/authorize?p=policy"},
		{name: "http endpoint", rawURL: "http://localhost:8080/auth", wantURL: "http://localhost:8080/auth"},
		{name: "userinfo rejected", rawURL: "https://user:pass@example.com/auth", wantError: true},
		{name: "fragment rejected", rawURL: "https://example.com/auth#fragment", wantError: true},
		{name: "relative rejected", rawURL: "/auth", wantError: true},
		{name: "unsupported scheme rejected", rawURL: "file:///tmp/auth", wantError: true},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			gotURL, err := ValidateOIDCEndpointURL(testCase.rawURL, "authorization endpoint")
			if testCase.wantError {
				if err == nil {
					t.Fatalf("ValidateOIDCEndpointURL(%q) returned nil error", testCase.rawURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateOIDCEndpointURL(%q) returned error: %v", testCase.rawURL, err)
			}
			if gotURL != testCase.wantURL {
				t.Fatalf("ValidateOIDCEndpointURL(%q) = %q, want %q", testCase.rawURL, gotURL, testCase.wantURL)
			}
		})
	}
}
