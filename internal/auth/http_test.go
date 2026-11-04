package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostJSONContextPreservesServerErrorMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestTimeout)
		_, _ = w.Write([]byte(`{"error":"login timed out"}`))
	}))
	defer server.Close()

	_, err := postJSONContext[struct{}](context.Background(), server.URL, nil)
	if err == nil || err.Error() != "login timed out" {
		t.Fatalf("postJSONContext() error = %v, want %q", err, "login timed out")
	}
}
