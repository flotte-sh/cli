package auth

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"

	"golang.org/x/term"
)

func PrintWarning(out io.Writer, message string, err error) {
	text := fmt.Sprintf("! WARNING: %s: %v\n", message, err)
	file, ok := out.(*os.File)
	if ok && term.IsTerminal(int(file.Fd())) && os.Getenv("TERM") != "" && os.Getenv("TERM") != "dumb" && os.Getenv("NO_COLOR") == "" && runtime.GOOS != "windows" && !testing.Testing() {
		text = "\x1b[33m! WARNING:\x1b[0m " + message + ": " + err.Error() + "\n"
	}
	fmt.Fprint(out, text)
}
