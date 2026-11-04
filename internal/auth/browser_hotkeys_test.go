package auth

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestBrowserHotkeysReleaseInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("browser hotkeys are disabled on Windows")
	}
	for _, cancelContext := range []bool{false, true} {
		input, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { input.Close(); writer.Close() })
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		stop, err := readAuthHotkeys(ctx, input, "https://example.invalid", io.Discard, cancel)
		if err != nil {
			t.Fatal(err)
		}
		if cancelContext {
			cancel()
		}
		done := make(chan struct{})
		go func() { stop(); stop(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("hotkey cleanup blocked waiting for input")
		}
		if _, err := writer.WriteString("2\n"); err != nil {
			t.Fatal(err)
		}
		if err := input.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 2)
		if _, err := io.ReadFull(input, buffer); err != nil || string(buffer) != "2\n" {
			t.Fatalf("next prompt input = %q, err = %v", buffer, err)
		}
	}
}

func TestAuthHotkeysCancel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("auth hotkeys are disabled on Windows")
	}
	for _, key := range []byte{3, 4} {
		t.Run(fmt.Sprintf("key-%d", key), func(t *testing.T) {
			input, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { input.Close(); writer.Close() })
			ctx, cancel := context.WithCancel(t.Context())
			stop, err := readAuthHotkeys(ctx, input, "", io.Discard, cancel)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			if _, err := writer.Write([]byte{key}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
				t.Fatalf("key %d did not cancel authentication", key)
			}
		})
	}
}
