package auth

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"

	"github.com/atotto/clipboard"
	"github.com/muesli/cancelreader"
	"golang.org/x/term"
)

func startBrowserHotkeys(ctx context.Context, loginURL string, out io.Writer, cancel context.CancelFunc) func() {
	return startAuthHotkeys(ctx, loginURL, out, cancel)
}

func startAuthorizationHotkeys(ctx context.Context, cancel context.CancelFunc) func() {
	return startAuthHotkeys(ctx, "", io.Discard, cancel)
}

func startAuthHotkeys(ctx context.Context, loginURL string, out io.Writer, cancel context.CancelFunc) func() {
	if runtime.GOOS == "windows" || !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return func() {}
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return func() {}
	}
	stop, err := readAuthHotkeys(ctx, os.Stdin, loginURL, out, cancel)
	if err != nil {
		_ = term.Restore(int(os.Stdin.Fd()), state)
		return func() {}
	}
	return func() {
		stop()
		_ = term.Restore(int(os.Stdin.Fd()), state)
	}
}

func readAuthHotkeys(ctx context.Context, in *os.File, loginURL string, out io.Writer, cancel context.CancelFunc) (func(), error) {
	reader, err := cancelreader.NewReader(in)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	stopContext := context.AfterFunc(ctx, func() { reader.Cancel() })
	go func() {
		defer close(done)
		buffer := []byte{0}
		for {
			if _, err := reader.Read(buffer); err != nil {
				return
			}
			switch buffer[0] {
			case 3, 4:
				cancel()
				return
			case 'x', 'X':
				if loginURL != "" {
					fmt.Fprintf(out, "\r\x1b[2KLogin link: %s\n", loginURL)
				}
			case 'c', 'C':
				if loginURL == "" {
					continue
				}
				if err := clipboard.WriteAll(loginURL); err != nil {
					fmt.Fprintf(out, "\r\x1b[2KCould not copy login link: %v\n", err)
				} else {
					fmt.Fprintln(out, "\r\x1b[2KLogin link copied.")
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			stopContext()
			reader.Cancel()
			<-done
			_ = reader.Close()
		})
	}, nil
}
