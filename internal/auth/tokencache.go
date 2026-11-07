package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/flotte-sh/cli/internal/config"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

const (
	tokenCacheFile = ".token.json"
	keyringService = "flotte-cli"
	keyringUser    = "opaque-token"
)

type cachedToken struct {
	Token string `json:"token"`
}

func LoadToken() (string, error) {
	if token, err := loadFromKeyring(); err == nil {
		return token, nil
	}
	return loadFromFile()
}

func SaveToken(token string) error {
	if err := saveToKeyring(token); err != nil {
		printAuthWarning(os.Stderr, "Keyring unavailable; falling back to file storage", err)
		return saveToFile(token)
	}
	if err := deleteFromFile(); err != nil {
		// best-effort cleanup: warn but keep the keyring-saved token
		printAuthWarning(os.Stderr, "Could not remove the token file", err)
	}
	return nil
}

func printAuthWarning(out io.Writer, message string, err error) {
	text := fmt.Sprintf("! WARNING: %s: %v\n", message, err)
	file, ok := out.(*os.File)
	if ok && term.IsTerminal(int(file.Fd())) && os.Getenv("TERM") != "" && os.Getenv("TERM") != "dumb" && os.Getenv("NO_COLOR") == "" && runtime.GOOS != "windows" && !testing.Testing() {
		text = "\x1b[33m! WARNING:\x1b[0m " + message + ": " + err.Error() + "\n"
	}
	fmt.Fprint(out, text)
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

func loadFromKeyring() (string, error) {
	secret, err := keyring.Get(keyringService, keyringUser)
	if err != nil {
		return "", err
	}
	if secret == "" {
		return "", fmt.Errorf("empty token in keyring")
	}
	return secret, nil
}

func saveToKeyring(token string) error {
	return keyring.Set(keyringService, keyringUser, token)
}

func deleteFromKeyring() error {
	err := keyring.Delete(keyringService, keyringUser)
	if err == keyring.ErrNotFound {
		return nil
	}
	return err
}

func loadFromFile() (string, error) {
	dir, err := config.GetConfigDir()
	if err != nil {
		return "", err
	}
	fp := filepath.Join(dir, tokenCacheFile)
	f, err := os.Open(fp) //#nosec G304
	if err != nil {
		return "", err
	}
	defer f.Close()
	var ct cachedToken
	if err := json.NewDecoder(f).Decode(&ct); err != nil {
		return "", err
	}
	if ct.Token == "" {
		return "", fmt.Errorf("empty token cache")
	}
	return ct.Token, nil
}

func saveToFile(token string) error {
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
	ct := cachedToken{Token: token}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(&ct)
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
