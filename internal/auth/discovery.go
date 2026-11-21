package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/flotte-sh/cli/internal/config"
)

type Discovery struct {
	BaseURL             string   `json:"baseUrl"`
	AuthMethods         []string `json:"authMethods"`
	PreferredAuthMethod string   `json:"preferredAuthMethod"`
	AuthMode            string   `json:"authMode"`
}

const (
	authMethodLoopback      = "loopback"
	authMethodDevice        = "device"
	authMethodLegacyBrowser = "browser"
)

var (
	errLegacyServer      = errors.New("this Flotte server only offers a browser sign-in that this CLI no longer supports for security reasons - update the Flotte server")
	errDeviceNotOffered  = errors.New("this Flotte server does not offer device sign-in - run 'flotte login' without --device")
	errDeviceNeedsOptIn  = errors.New("this Flotte server only offers device sign-in, which the CLI never starts on its own - run 'flotte login --device'")
	errNoSupportedMethod = errors.New("server advertises no supported authentication methods")
)

func (d Discovery) methods() ([]string, error) {
	methods := d.AuthMethods
	preferred := d.PreferredAuthMethod
	if methods == nil && preferred == "" {
		methods = []string{d.AuthMode}
		preferred = d.AuthMode
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("server advertises no authentication methods")
	}
	if preferred != "" && !slices.Contains(methods, preferred) {
		return nil, fmt.Errorf("preferred authentication method %q is not advertised", preferred)
	}
	return methods, nil
}

// Method picks how to sign in. The server's preference is ignored on purpose:
// device sign-in hands the session to whoever started it, so it is only used
// when the user asked for it, and never because a server said so.
func (d Discovery) Method(deviceRequested bool) (string, error) {
	methods, err := d.methods()
	if err != nil {
		return "", err
	}
	offersDevice := slices.Contains(methods, authMethodDevice)
	offersLoopback := slices.Contains(methods, authMethodLoopback)
	switch {
	case deviceRequested && offersDevice:
		return authMethodDevice, nil
	case deviceRequested && offersLoopback:
		return "", errDeviceNotOffered
	case offersLoopback:
		return authMethodLoopback, nil
	case offersDevice:
		return "", errDeviceNeedsOptIn
	case slices.Contains(methods, authMethodLegacyBrowser):
		return "", errLegacyServer
	default:
		return "", errNoSupportedMethod
	}
}

func (d Discovery) validate() error {
	_, err := d.Method(false)
	if errors.Is(err, errDeviceNeedsOptIn) {
		return nil
	}
	return err
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
	return discovery, discovery.validate()
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
		return cached.discovery.Method(deviceSignInRequested(ctx))
	}
	discovery, err := Discover(ctx, serverURL)
	if err != nil {
		return "", err
	}
	return discovery.Method(deviceSignInRequested(ctx))
}
