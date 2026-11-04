package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flotte-sh/flotte-cli/internal/config"
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
