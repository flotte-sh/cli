package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/flotte-sh/cli/internal/config"
	"github.com/zalando/go-keyring"
)

const (
	tokenCacheFile = ".token.json"
	keyringService = "flotte-cli"
	keyringUser    = "opaque-token"
)

type Session struct {
	Token  string `json:"token"`
	Server string `json:"server,omitempty"`
}

var errOtherServer = errors.New("the cached session does not belong to this Flotte server")

func LoadSession() (Session, error) {
	if session, err := loadFromKeyring(); err == nil {
		return session, nil
	}
	return loadFromFile()
}

func LoadToken(serverURL string) (string, error) {
	session, err := LoadSession()
	if err != nil {
		return "", err
	}
	if !sameServer(session.Server, serverURL) {
		return "", errOtherServer
	}
	return session.Token, nil
}

func sameServer(left, right string) bool {
	left, err := config.NormalizeFlotteURL(left)
	if err != nil {
		return false
	}
	right, err = config.NormalizeFlotteURL(right)
	return err == nil && left == right
}

func SaveToken(serverURL, token string) error {
	server, err := config.NormalizeFlotteURL(serverURL)
	if err != nil {
		return fmt.Errorf("cannot tie the session to the server URL: %w", err)
	}
	session := Session{Token: token, Server: server}
	if err := saveToKeyring(session); err != nil {
		PrintWarning(os.Stderr, "Keyring unavailable; falling back to file storage", err)
		return saveToFile(session)
	}
	if err := deleteFromFile(); err != nil {
		// best-effort cleanup: warn but keep the keyring-saved token
		PrintWarning(os.Stderr, "Could not remove the token file", err)
	}
	return nil
}

func DeleteToken() error {
	_, keyringLoadErr := loadFromKeyring()
	_, fileLoadErr := loadFromFile()
	errKR := deleteFromKeyring()
	errFile := deleteFromFile()
	if keyringLoadErr == nil && errKR != nil {
		return fmt.Errorf("failed to delete token from keyring: %v", errKR)
	}
	if fileLoadErr == nil && errFile != nil {
		return fmt.Errorf("failed to delete token file: %v", errFile)
	}
	if errKR != nil && errFile != nil {
		return fmt.Errorf("failed to delete token from keyring: %v; file: %v", errKR, errFile)
	}
	return nil
}

func loadFromKeyring() (Session, error) {
	secret, err := keyring.Get(keyringService, keyringUser)
	if err != nil {
		return Session{}, err
	}
	if secret == "" {
		return Session{}, fmt.Errorf("empty token in keyring")
	}
	var session Session
	if err := json.Unmarshal([]byte(secret), &session); err != nil || session.Token == "" {
		// Older CLIs stored the bare token. Without its server it is never sent anywhere.
		return Session{Token: secret}, nil
	}
	return session, nil
}

func saveToKeyring(session Session) error {
	secret, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return keyring.Set(keyringService, keyringUser, string(secret))
}

func deleteFromKeyring() error {
	err := keyring.Delete(keyringService, keyringUser)
	if err == keyring.ErrNotFound {
		return nil
	}
	return err
}

func loadFromFile() (Session, error) {
	dir, err := config.GetConfigDir()
	if err != nil {
		return Session{}, err
	}
	fp := filepath.Join(dir, tokenCacheFile)
	f, err := os.Open(fp) //#nosec G304
	if err != nil {
		return Session{}, err
	}
	defer f.Close()
	var session Session
	if err := json.NewDecoder(f).Decode(&session); err != nil {
		return Session{}, err
	}
	if session.Token == "" {
		return Session{}, fmt.Errorf("empty token cache")
	}
	return session, nil
}

func saveToFile(session Session) error {
	dir, err := config.GetConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fp := filepath.Join(dir, tokenCacheFile)
	f, err := os.OpenFile(fp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //#nosec G304
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(&session)
}

func deleteFromFile() error {
	dir, err := config.GetConfigDir()
	if err != nil {
		return err
	}
	fp := filepath.Join(dir, tokenCacheFile)
	err = os.Remove(fp)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
