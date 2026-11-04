package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

const (
	sshKeyDir          = "ssh"
	privateKeyFileName = "id_ed25519"
	publicKeyFileName  = "id_ed25519.pub"
)

// GetSSHKeyDir returns the directory where SSH keys are stored
func GetSSHKeyDir() (string, error) {
	storagePath, err := GetStoragePath()
	if err != nil {
		return "", err
	}
	// Get the .flotte directory from the storage path
	flotteDir := filepath.Dir(storagePath)
	return filepath.Join(flotteDir, sshKeyDir), nil
}

func WriteKnownHosts(host string, port string, hostkeys []string) error {
	keyDir, err := GetSSHKeyDir()
	if err != nil {
		return fmt.Errorf("failed to get ssh key dir: %w", err)
	}

	filePath := filepath.Join(keyDir, "known_hosts")

	hostkeysContent := ""
	for _, v := range hostkeys {
		khHost := host
		if port != "22" {
			khHost = "[" + host + "]:" + port
		}

		hostkeysContent += fmt.Sprintf("%s %s\n", khHost, v)
	}

	err = os.WriteFile(filePath, []byte(hostkeysContent), 0o600)
	if err != nil {
		return fmt.Errorf("error writing known_hosts file: %w", err)
	}

	return nil
}

// EnsureSSHKeys ensures SSH keys exist, generating them if needed
func EnsureSSHKeys() error {
	keyDir, err := GetSSHKeyDir()
	if err != nil {
		return fmt.Errorf("failed to get SSH key directory: %w", err)
	}

	// Create SSH key directory if it doesn't exist
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return fmt.Errorf("failed to create SSH key directory: %w", err)
	}

	privateKeyPath := filepath.Join(keyDir, privateKeyFileName)
	publicKeyPath := filepath.Join(keyDir, publicKeyFileName)

	// Check if keys already exist
	if _, err := os.Stat(privateKeyPath); err == nil {
		if _, err := os.Stat(publicKeyPath); err == nil {
			// Both keys exist
			return nil
		}
	}

	// Generate new ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}

	// Convert to SSH format
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to create SSH public key: %w", err)
	}

	// Write public key
	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)
	if err := os.WriteFile(publicKeyPath, pubKeyBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	// Encode private key in OpenSSH format
	privKeyBytes, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Write private key
	privKeyPEM := pem.EncodeToMemory(privKeyBytes)
	if err := os.WriteFile(privateKeyPath, privKeyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// GetActiveSSHPrivateKeyPath returns the path to the private key
func GetActiveSSHPrivateKeyPath() (string, error) {
	if err := EnsureSSHKeys(); err != nil {
		return "", err
	}
	keyDir, err := GetSSHKeyDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(keyDir, privateKeyFileName), nil
}

// GetActiveSSHPubKeyPath returns the path to the public key
func GetActiveSSHPubKeyPath() (string, error) {
	if err := EnsureSSHKeys(); err != nil {
		return "", err
	}
	keyDir, err := GetSSHKeyDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(keyDir, publicKeyFileName), nil
}

func GetActiveSSHPublicKey() (string, error) {
	pubKeyPath, err := GetActiveSSHPubKeyPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(pubKeyPath) //#nosec G304 -- reading user's SSH public key from known location
	if err != nil {
		return "", err
	}
	return string(data), nil
}
