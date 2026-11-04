package winscp

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/flotte-sh/flotte-cli/integrations/internal/target"
)

type Options struct {
	Executable string
	ServerURL  string
	Token      string
	User       string
	Address    string
	Input      io.Reader
	Output     io.Writer
	Errors     io.Writer
}

func winSCPSessionURL(loginUser, address string) (string, error) {
	if loginUser == "" || strings.ContainsFunc(loginUser, unicode.IsControl) {
		return "", fmt.Errorf("invalid WinSCP username")
	}
	host, port, err := target.Split(address)
	if err != nil {
		return "", fmt.Errorf("invalid WinSCP target: %w", err)
	}
	session := url.URL{Scheme: "sftp", User: url.User(loginUser), Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: "/"}
	return session.String(), nil
}
