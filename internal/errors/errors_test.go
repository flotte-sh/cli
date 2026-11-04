package errors

import (
	stderrors "errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestGetUserMessagePrefersCliUserMessage(t *testing.T) {
	inner := Wrap("auth", stderrors.New("context deadline exceeded"), "browser authentication failed: browser auth timed out. Retry with 'flotte login'.")
	outer := Wrap("ssh", inner, GetUserMessage(inner))

	got := GetUserMessage(outer)
	want := "browser authentication failed: browser auth timed out. Retry with 'flotte login'."
	if got != want {
		t.Fatalf("GetUserMessage() = %q, want %q", got, want)
	}
	if outer != inner {
		t.Fatalf("Wrap() should return the existing error when the user message is unchanged")
	}
}

func TestWrapfReturnsExistingCliErrorWhenUserMessageUnchanged(t *testing.T) {
	inner := New("client", stderrors.New("dial tcp timeout"), "failed to connect to server - check your network connection")
	outer := Wrapf("ssh", inner, "%s", GetUserMessage(inner))

	if outer != inner {
		t.Fatalf("Wrapf() should return the existing error when the formatted user message is unchanged")
	}
}

func TestGetUserMessageFallsBackToPlainError(t *testing.T) {
	err := stderrors.New("plain failure")

	got := GetUserMessage(err)
	if got != err.Error() {
		t.Fatalf("GetUserMessage() = %q, want %q", got, err.Error())
	}
}

func TestParseApiErrorUsesActionableStatusMessages(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		wantContains []string
	}{
		{
			name:         "unauthorized suggests login",
			statusCode:   http.StatusUnauthorized,
			wantContains: []string{"session expired", "flotte login"},
		},
		{
			name:         "not found suggests setup check",
			statusCode:   http.StatusNotFound,
			wantContains: []string{"resource not found", "flotte setup <server-url>"},
		},
		{
			name:         "forbidden suggests administrator",
			statusCode:   http.StatusForbidden,
			wantContains: []string{"access denied", "Flotte administrator"},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: testCase.statusCode,
				Body:       io.NopCloser(strings.NewReader("backend failure")),
			}

			got := GetUserMessage(ParseApiError(resp))
			for _, want := range testCase.wantContains {
				if !strings.Contains(got, want) {
					t.Fatalf("ParseApiError(%d) = %q, want substring %q", testCase.statusCode, got, want)
				}
			}
		})
	}
}

func TestParseApiErrorBoundsBodyRead(t *testing.T) {
	body := &countingReader{reader: strings.NewReader(`{"error":"` + strings.Repeat("x", maxAPIErrorBodySize) + `"}`)}
	resp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Body:       io.NopCloser(body),
	}

	got := GetUserMessage(ParseApiError(resp))
	if body.read > maxAPIErrorBodySize {
		t.Fatalf("ParseApiError read %d bytes, want at most %d", body.read, maxAPIErrorBodySize)
	}
	if want := statusCodeToMessage(http.StatusBadRequest); got != want {
		t.Fatalf("ParseApiError() = %q, want %q", got, want)
	}
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	c.read += n
	return n, err
}

func TestParseApiErrorPrefersServerProvidedMessage(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Body:       io.NopCloser(strings.NewReader(`{"error":"access denied by policy"}`)),
	}

	got := GetUserMessage(ParseApiError(resp))
	if got != "access denied by policy" {
		t.Fatalf("ParseApiError() = %q, want %q", got, "access denied by policy")
	}
}
