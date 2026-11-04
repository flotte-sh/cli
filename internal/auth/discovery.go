package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/flotte-sh/flotte-cli/internal/config"
)

type Discovery struct {
	BaseURL             string   `json:"baseUrl"`
	AuthMethods         []string `json:"authMethods"`
	PreferredAuthMethod string   `json:"preferredAuthMethod"`
	AuthMode            string   `json:"authMode"`
}

const (
	authMethodBrowser = "browser"
	authMethodDevice  = "device"
)

func (d Discovery) Method() (string, error) {
	methods := d.AuthMethods
	preferred := d.PreferredAuthMethod
	if methods == nil && preferred == "" {
		methods = []string{d.AuthMode}
		preferred = d.AuthMode
	}
	if len(methods) == 0 {
		return "", fmt.Errorf("server advertises no authentication methods")
	}
	if preferred != "" && !slices.Contains(methods, preferred) {
		return "", fmt.Errorf("preferred authentication method %q is not advertised", preferred)
	}
	if preferred == authMethodBrowser || preferred == authMethodDevice {
		return preferred, nil
	}
	for _, method := range []string{authMethodBrowser, authMethodDevice} {
		if slices.Contains(methods, method) {
			return method, nil
		}
	}
	return "", fmt.Errorf("server advertises no supported authentication methods")
}

func Discover(ctx context.Context, serverURL string) (Discovery, error) {
	var discovery Discovery
	endpoint, err := config.JoinEndpoint(serverURL, "/.well-known/cli-config")
	if err != nil {
		return discovery, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return discovery, err
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return discovery, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return discovery, fmt.Errorf("discovery returned HTTP %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(&discovery); err != nil {
		return discovery, fmt.Errorf("invalid CLI discovery: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return discovery, fmt.Errorf("invalid trailing CLI discovery data")
	}
	if discovery.BaseURL != "" {
		discovery.BaseURL, err = config.NormalizeFlotteURL(discovery.BaseURL)
		if err != nil {
			return discovery, fmt.Errorf("invalid discovery base URL: %w", err)
		}
	}
	_, err = discovery.Method()
	return discovery, err
}

type discoveryKey struct{}

type discoveredServer struct {
	url       string
	discovery Discovery
}

func WithDiscovery(ctx context.Context, serverURL string, discovery Discovery) context.Context {
	return context.WithValue(ctx, discoveryKey{}, discoveredServer{serverURL, discovery})
}

func discoverMethod(ctx context.Context, serverURL string) (string, error) {
	if cached, ok := ctx.Value(discoveryKey{}).(discoveredServer); ok && cached.url == serverURL {
		return cached.discovery.Method()
	}
	discovery, err := Discover(ctx, serverURL)
	if err != nil {
		return "", err
	}
	return discovery.Method()
}
