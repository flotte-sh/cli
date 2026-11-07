package putty

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	"github.com/flotte-sh/cli/integrations/internal/target"
	"golang.org/x/crypto/ssh"
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

func launchArguments(loginUser, address string, approvedHostKeys []ssh.PublicKey) ([]string, error) {
	if loginUser == "" || strings.ContainsFunc(loginUser, unicode.IsControl) {
		return nil, fmt.Errorf("invalid PuTTY username")
	}
	host, port, err := target.Split(address)
	if err != nil {
		return nil, fmt.Errorf("invalid PuTTY target: %w", err)
	}
	if strings.HasPrefix(host, "-") {
		return nil, fmt.Errorf("invalid PuTTY hostname")
	}
	if len(approvedHostKeys) == 0 {
		return nil, fmt.Errorf("invalid PuTTY host key")
	}
	targetHost := host
	if strings.Contains(host, ":") {
		targetHost = "[" + host + "]"
	}
	arguments := []string{
		"-ssh", "-agent", "-a", "-noshare",
		"-l", loginUser,
		"-P", strconv.Itoa(port),
		"-i", "",
		"-cert", "",
	}
	for _, approvedHostKey := range approvedHostKeys {
		if approvedHostKey == nil {
			return nil, fmt.Errorf("invalid PuTTY host key")
		}
		arguments = append(arguments, "-hostkey", ssh.FingerprintSHA256(approvedHostKey))
	}
	return append(arguments, targetHost), nil
}
