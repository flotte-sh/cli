package sshhelper

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func addHostkey(k *string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		keyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		*k = keyStr
		return fmt.Errorf("hostkey added successfully") // make sure the connection is terminated early
	}
}

func QueryServerHostkey(address string) (string, error) {
	key := ""

	config := &ssh.ClientConfig{
		User: "flotte-keyscan",
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoRSASHA256,
			ssh.KeyAlgoRSASHA512,
			ssh.KeyAlgoRSA,
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoSKECDSA256,
			ssh.KeyAlgoSKED25519,
		}, HostKeyCallback: addHostkey(&key),
		Timeout: 5 * time.Second,
	}

	conn, err := ssh.Dial("tcp", address, config)
	if err == nil {
		_ = conn.Close()
	}

	if key == "" {
		return "", fmt.Errorf("no hostkey found. is the server reachable?")
	}

	return key, nil
}
