package auth

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/term"
)

func authorizationWaitSupported(outputTTY bool, terminal string, noColor, underTest bool, platform string) bool {
	return outputTTY && terminal != "" && terminal != "dumb" && !noColor && !underTest && platform != "windows"
}

func startAuthorizationWait(out io.Writer) func() {
	file, ok := out.(*os.File)
	outputTTY := ok && term.IsTerminal(int(file.Fd()))
	_, noColor := os.LookupEnv("NO_COLOR")
	return startAuthorizationSpinner(out, authorizationWaitSupported(outputTTY, os.Getenv("TERM"), noColor, testing.Testing(), runtime.GOOS))
}

func startAuthorizationSpinner(out io.Writer, animate bool) func() {
	if !animate {
		fmt.Fprintln(out, "Waiting for authorization...")
		return func() {}
	}

	const frames = ".oOo"
	draw := func(frame int) {
		fmt.Fprintf(out, "\r\x1b[2K\x1b[36m%c\x1b[0m Waiting for authorization...", frames[frame])
	}
	draw(0)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for frame := 1; ; {
			select {
			case <-stop:
				fmt.Fprint(out, "\r\x1b[2K")
				return
			case <-ticker.C:
				draw(frame)
				frame = (frame + 1) % len(frames)
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(stop) })
		<-done
	}
}
