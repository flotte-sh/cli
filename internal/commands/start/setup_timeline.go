package start

import (
	"io"
	"os"
	"runtime"

	"golang.org/x/term"
)

type setupView struct {
	color bool
}

func newSetupTimeline(out io.Writer) setupView {
	_, noColor := os.LookupEnv("NO_COLOR")
	color, _ := setupCapabilities(isSetupTerminal(out), false, os.Getenv("TERM"), noColor, runtime.GOOS)
	return setupView{color: color}
}

func isSetupTerminal(stream any) bool {
	file, ok := stream.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func setupCapabilities(outputTTY, inputTTY bool, terminal string, noColor bool, platform string) (bool, bool) {
	color := outputTTY && terminal != "" && terminal != "dumb" && !noColor && platform != "windows"
	return color, inputTTY
}

func (view setupView) accent(text string) string {
	if !view.color {
		return text
	}
	return "\x1b[1;36m" + text + "\x1b[0m"
}
