package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flotte-sh/cli/internal/config"
)

func TestRequestCertificateCancellation(t *testing.T) {
	for _, flushResponse := range []bool{false, true} {
		name := "waiting-for-headers"
		if flushResponse {
			name = "reading-response-body"
		}
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{})
			cancelled := make(chan struct{})
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if _, err := io.Copy(io.Discard, request.Body); err != nil {
					t.Errorf("read certificate request: %v", err)
					return
				}
				if flushResponse {
					writer.Header().Set("Content-Type", "application/json")
					_, _ = writer.Write([]byte(`{"certificate":`))
					writer.(http.Flusher).Flush()
				}
				close(started)
				select {
				case <-request.Context().Done():
					close(cancelled)
				case <-release:
				}
			}))
			defer server.Close()
			defer close(release)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := RequestCertificate(ctx, &config.ClientConfig{FlotteUrl: server.URL}, "token", "public-key", "host-key", "alice")
				result <- err
			}()
			timeout := time.NewTimer(5 * time.Second)
			defer timeout.Stop()
			select {
			case <-started:
			case <-timeout.C:
				t.Fatal("certificate request did not reach the server")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected wrapped context cancellation, got %v", err)
				}
			case <-timeout.C:
				t.Fatal("cancellation did not interrupt the certificate response")
			}
			select {
			case <-cancelled:
			case <-timeout.C:
				t.Fatal("server request context was not cancelled")
			}
		})
	}
}

func TestSessionRequestsNeverFollowARedirect(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var elsewhere atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				elsewhere.Add(1)
				_, _ = writer.Write([]byte(`{"authenticated":true,"certificate":"forged"}`))
			}))
			defer other.Close()
			var received atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				received.Add(1)
				http.Redirect(writer, request, other.URL+request.URL.Path, status)
			}))
			defer server.Close()
			cfg := &config.ClientConfig{FlotteUrl: server.URL}

			if info, err := FetchUserInfo(t.Context(), cfg, "token"); err == nil {
				t.Fatalf("FetchUserInfo followed the redirect: %+v", info)
			} else if !strings.Contains(err.Error(), "redirected") {
				t.Fatalf("FetchUserInfo error = %v", err)
			}
			if certificate, err := RequestCertificate(t.Context(), cfg, "token", "public-key", "host-key", "alice"); err == nil {
				t.Fatalf("RequestCertificate followed the redirect: %+v", certificate)
			}
			if err := RevokeToken(cfg, "token"); err == nil {
				t.Fatal("RevokeToken reported success for a redirect")
			}
			if received.Load() != 3 || elsewhere.Load() != 0 {
				t.Fatalf("requests to the server = %d, requests sent elsewhere = %d", received.Load(), elsewhere.Load())
			}
		})
	}
}
