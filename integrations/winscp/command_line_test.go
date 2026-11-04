package winscp

import "testing"

func TestWinSCPCommandLinePreservesEmbeddedPuTTYQuotes(t *testing.T) {
	arguments := []string{`C:\Program Files\WinSCP\WinSCP.exe`, `/rawconfig`, `Interface\Setting="C:\Program Files\App\app.exe" -agent -hostkey "SHA256:abc" -l !U`}
	want := `"C:\Program Files\WinSCP\WinSCP.exe" "/rawconfig" "Interface\Setting=""C:\Program Files\App\app.exe"" -agent -hostkey ""SHA256:abc"" -l !U"`
	if got := winSCPCommandLine(arguments); got != want {
		t.Fatalf("command line = %q, want WinSCP doubled-quote syntax %q", got, want)
	}
}

func TestWinSCPCommandLineDoesNotApplyCRTBackslashEscapes(t *testing.T) {
	arguments := []string{`winscp.exe`, `C:\trailing slash\`, `name" -rawconfig evil`, ""}
	want := `"winscp.exe" "C:\trailing slash\" "name"" -rawconfig evil" ""`
	if got := winSCPCommandLine(arguments); got != want {
		t.Fatalf("command line changes WinSCP token boundaries: %q, want %q", got, want)
	}
}
