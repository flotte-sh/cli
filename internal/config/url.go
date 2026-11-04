package config

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

func NormalizeFlotteURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("server URL is required")
	}
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		trimmed = "https://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("missing host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("user info is not allowed")
	}
	if parsed.RawQuery != "" {
		return "", fmt.Errorf("query is not allowed")
	}
	if parsed.Fragment != "" {
		return "", fmt.Errorf("fragment is not allowed")
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	parsed.ForceQuery = false
	return parsed.String(), nil
}

func JoinEndpoint(baseURL string, endpointPath string) (string, error) {
	normalized, err := NormalizeFlotteURL(baseURL)
	if err != nil {
		return "", err
	}

	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", err
	}

	parts := []string{parsed.Path}
	for _, part := range strings.Split(endpointPath, "/") {
		if part == "" {
			continue
		}
		parts = append(parts, part)
	}
	parsed.Path = path.Join(parts...)
	if !strings.HasPrefix(parsed.Path, "/") {
		parsed.Path = "/" + parsed.Path
	}
	parsed.RawPath = ""
	return parsed.String(), nil
}
