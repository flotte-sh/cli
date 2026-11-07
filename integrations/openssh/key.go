package openssh

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/flotte-sh/cli/internal/config"
	"golang.org/x/crypto/ssh"
)

func LoadCLIPrivateKey() (ed25519.PrivateKey, error) {
	path, err := config.GetActiveSSHPrivateKeyPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- Path is the fixed CLI key location returned by config, not an SSH hook argument.
	if err != nil {
		return nil, fmt.Errorf("read Flotte CLI private key: %w", err)
	}
	parsed, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse Flotte CLI private key: %w", err)
	}
	private, ok := parsed.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("flotte CLI private key must be Ed25519")
	}
	return *private, nil
}
