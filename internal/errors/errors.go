package errors

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type userMessageError struct {
	message string
	err     error
}

func (e *userMessageError) Error() string {
	if e.err == nil {
		return e.message
	}
	return fmt.Sprintf("%s: %v", e.message, e.err)
}

func (e *userMessageError) Unwrap() error {
	return e.err
}

func (e *userMessageError) UserMessage() string {
	return e.message
}

func New(_ string, internalErr error, userMessage string) error {
	if userMessage == "" {
		if internalErr != nil {
			return internalErr
		}
		return errors.New("")
	}
	return &userMessageError{message: userMessage, err: internalErr}
}

func Newf(_ string, internalErr error, format string, args ...any) error {
	message := fmt.Sprintf(format, args...)
	if message == "" {
		if internalErr != nil {
			return internalErr
		}
		return errors.New("")
	}
	return &userMessageError{message: message, err: internalErr}
}

func Wrap(_ string, err error, userMessage string) error {
	if userMessage == "" {
		return err
	}
	if err != nil && GetUserMessage(err) == userMessage {
		return err
	}
	return &userMessageError{message: userMessage, err: err}
}

func Wrapf(_ string, err error, format string, args ...any) error {
	userMessage := fmt.Sprintf(format, args...)
	if userMessage == "" {
		return err
	}
	if err != nil && GetUserMessage(err) == userMessage {
		return err
	}
	return &userMessageError{message: userMessage, err: err}
}

// ApiErrorResponse matches the JSON error format returned by the Flotte API.
type ApiErrorResponse struct {
	Error string `json:"error"`
}

type APIError struct {
	StatusCode int
	Message    string
}

func (err *APIError) Error() string {
	return err.Message
}

const maxAPIErrorBodySize = 1 << 20

func ParseApiError(resp *http.Response) error {
	if resp.Body == nil {
		return &APIError{StatusCode: resp.StatusCode, Message: statusCodeToMessage(resp.StatusCode)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIErrorBodySize))
	if err != nil {
		return &APIError{StatusCode: resp.StatusCode, Message: statusCodeToMessage(resp.StatusCode)}
	}

	var apiErr ApiErrorResponse
	if err := json.Unmarshal(body, &apiErr); err == nil && apiErr.Error != "" {
		return &APIError{StatusCode: resp.StatusCode, Message: apiErr.Error}
	}

	return &APIError{StatusCode: resp.StatusCode, Message: statusCodeToMessage(resp.StatusCode)}
}

// statusCodeToMessage returns a user-friendly message for common HTTP status codes.
func statusCodeToMessage(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "request was rejected by the server - check the command arguments and try again"
	case http.StatusUnauthorized:
		return "authentication required or session expired - run 'flotte login' and retry"
	case http.StatusForbidden:
		return "access denied - verify your account permissions or ask a Flotte administrator"
	case http.StatusNotFound:
		return "resource not found - check the target value or rerun 'flotte setup <server-url>' if the server URL changed"
	case http.StatusConflict:
		return "resource conflict - review the existing resource and retry"
	case http.StatusInternalServerError:
		return "server error - retry in a moment; if it persists, contact your Flotte administrator"
	case http.StatusServiceUnavailable:
		return "service temporarily unavailable - retry in a moment or check whether the Flotte server is up"
	default:
		return fmt.Sprintf("unexpected server response (status %d) - retry once, then inspect the server logs if it keeps happening", code)
	}
}

func GetUserMessage(err error) string {
	if err == nil {
		return ""
	}

	var userErr interface {
		UserMessage() string
	}
	if errors.As(err, &userErr) {
		return userErr.UserMessage()
	}

	return err.Error()
}

// RootCause returns the message of the innermost error in the chain.
func RootCause(err error) string {
	if err == nil {
		return ""
	}
	cause := err
	for {
		next := errors.Unwrap(cause)
		if next == nil {
			break
		}
		cause = next
	}
	return cause.Error()
}
