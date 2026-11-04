package auth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestAuthorizationWaitCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name               string
		tty                bool
		term               string
		noColor, underTest bool
		platform           string
		want               bool
	}{
		{"linux", true, "xterm-256color", false, false, "linux", true},
		{"darwin", true, "xterm", false, false, "darwin", true},
		{"pipe", false, "xterm", false, false, "linux", false},
		{"unset", true, "", false, false, "linux", false},
		{"dumb", true, "dumb", false, false, "linux", false},
		{"no color", true, "xterm", true, false, "linux", false},
		{"test", true, "xterm", false, true, "linux", false},
		{"windows", true, "xterm", false, false, "windows", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizationWaitSupported(tc.tty, tc.term, tc.noColor, tc.underTest, tc.platform); got != tc.want {
				t.Fatalf("supported = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAuthorizationWaitStatic(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	var out bytes.Buffer
	stop := startAuthorizationWait(&out)
	stop()
	stop()
	if got := out.String(); got != "Waiting for authorization...\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestAuthorizationSpinnerLifecycle(t *testing.T) {
	for _, result := range []error{nil, errors.New("exchange failed"), context.Canceled} {
		synctest.Test(t, func(t *testing.T) {
			var out bytes.Buffer
			got := func() error {
				stop := startAuthorizationSpinner(&out, true)
				defer stop()
				synctest.Wait()
				time.Sleep(400 * time.Millisecond)
				synctest.Wait()
				return result
			}()
			if got != result {
				t.Fatalf("result = %v, want %v", got, result)
			}
			text := out.String()
			for _, frame := range ".oOo" {
				if !strings.Contains(text, "\x1b[36m"+string(frame)+"\x1b[0m Waiting for authorization...") {
					t.Fatalf("missing frame %q in %q", frame, text)
				}
			}
			if !strings.HasSuffix(text, "\r\x1b[2K") || strings.Contains(text, "\x1b[?25") {
				t.Fatalf("unexpected cleanup or cursor control: %q", text)
			}
			time.Sleep(time.Second)
			if out.String() != text {
				t.Fatal("output changed after cleanup")
			}
		})
	}
}

func TestAuthorizationSpinnerImmediateConcurrentStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out bytes.Buffer
		stop := startAuthorizationSpinner(&out, true)
		var callers sync.WaitGroup
		for range 8 {
			callers.Go(stop)
		}
		callers.Wait()
		stop()
		if strings.Count(out.String(), "Waiting for authorization...") != 1 || !strings.HasSuffix(out.String(), "\r\x1b[2K") {
			t.Fatalf("unexpected output: %q", out.String())
		}
	})
}
