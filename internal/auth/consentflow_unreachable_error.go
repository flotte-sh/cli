package auth

import "fmt"

type consentUnreachableError struct{ cause error }

func (e *consentUnreachableError) Error() string {
	return fmt.Sprintf("failed to reach the server to complete sign-in: %v", e.cause)
}

func (e *consentUnreachableError) Unwrap() error { return e.cause }
