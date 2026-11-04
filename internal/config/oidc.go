package config

import (
	"fmt"
	"net/url"
	"strings"
)

func ValidateOIDCEndpointURL(rawURL, name string) (string, error) {
	trimmedURL := strings.TrimSpace(rawURL)
	if trimmedURL == "" {
		return "", nil
	}
	if strings.Contains(trimmedURL, "#") {
		return "", fmt.Errorf("invalid %s URL: fragments are not allowed", name)
	}

	parsedURL, err := url.ParseRequestURI(trimmedURL)
	if err != nil {
		return "", fmt.Errorf("invalid %s URL: %w", name, err)
	}
	if !parsedURL.IsAbs() {
		return "", fmt.Errorf("invalid %s URL: must be absolute", name)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("invalid %s URL: unsupported scheme %q", name, parsedURL.Scheme)
	}
	if parsedURL.Host == "" {
		return "", fmt.Errorf("invalid %s URL: missing host", name)
	}
	if parsedURL.User != nil {
		return "", fmt.Errorf("invalid %s URL: user info is not allowed", name)
	}

	return parsedURL.String(), nil
}
