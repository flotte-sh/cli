package start

import "testing"

func TestSetupCapabilities(t *testing.T) {
	for _, tt := range []struct {
		name                       string
		outputTTY, inputTTY        bool
		terminal                   string
		noColor                    bool
		platform                   string
		wantColor, wantInteractive bool
	}{
		{"interactive", true, true, "xterm-256color", false, "linux", true, true},
		{"macOS", true, true, "xterm-256color", false, "darwin", true, true},
		{"redirected output", false, true, "xterm", false, "linux", false, true},
		{"redirected input", true, false, "xterm", false, "linux", true, false},
		{"no color", true, true, "xterm", true, "linux", false, true},
		{"dumb", true, true, "dumb", false, "linux", false, true},
		{"unknown terminal", true, true, "", false, "linux", false, true},
		{"windows without VT detection", true, true, "xterm", false, "windows", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			color, animate := setupCapabilities(tt.outputTTY, tt.inputTTY, tt.terminal, tt.noColor, tt.platform)
			if color != tt.wantColor || animate != tt.wantInteractive {
				t.Fatalf("capabilities = (%t, %t), want (%t, %t)", color, animate, tt.wantColor, tt.wantInteractive)
			}
		})
	}
}
