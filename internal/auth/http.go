package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	clierrors "github.com/flotte-sh/flotte-cli/internal/errors"
)

const maxResponseBodySize = 1 << 20 // 1 MiB — enough for token responses, blocks unbounded reads

var httpClient = &http.Client{Timeout: 10 * time.Minute} // must exceed the server's 10-min flow TTL

func postJSONContext[T any](ctx context.Context, url string, body []byte) (*T, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req) //#nosec G107 URL is server-configured, not attacker-controlled
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, clierrors.ParseApiError(resp)
	}

	var result T
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodySize)).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
