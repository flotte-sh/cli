package target

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

func Split(address string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("invalid target (use host:port or [IPv6]:port): %w", err)
	}
	if host == "" || strings.ContainsAny(host, "/\\%?#@<>\"") || strings.ContainsFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return "", 0, fmt.Errorf("invalid target hostname")
	}
	number, err := strconv.Atoi(port)
	if err != nil || strings.ContainsAny(port, "+-") || number < 1 || number > 65535 {
		return "", 0, fmt.Errorf("invalid target port: %q", port)
	}
	return host, number, nil
}
