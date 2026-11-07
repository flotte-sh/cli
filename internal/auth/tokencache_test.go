package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/flotte-sh/cli/internal/config"
	"github.com/zalando/go-keyring"
)

var errNoKeyring = errors.New("keyring unavailable: no keyring provider found")

// ---------------------------------------------------------------------------
// DeleteToken
// ---------------------------------------------------------------------------

func TestDeleteToken_NoKeyring_FileOnly(t *testing.T) {
	keyring.MockInitWithError(errNoKeyring)
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	token := "test-token-123"
	if err := SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	if err := DeleteToken(); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}

	_, err := LoadToken()
	if err == nil {
		t.Fatal("expected error loading token after deletion")
	}
}

func TestDeleteToken_KeyringAvailable(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	token := "test-token-keyring"
	if err := SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	if err := DeleteToken(); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}

	_, err := LoadToken()
	if err == nil {
		t.Fatal("expected error loading token after deletion")
	}
}

func TestDeleteToken_NoTokenExists(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := DeleteToken(); err != nil {
		t.Fatalf("DeleteToken with no token: %v", err)
	}
}

func TestDeleteToken_TokenInFile_KeyringFails(t *testing.T) {
	keyring.MockInitWithError(errNoKeyring)
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	token := "file-only-token"
	if err := SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	loaded, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken before delete: %v", err)
	}
	if loaded != token {
		t.Fatalf("got %q, want %q", loaded, token)
	}

	if err := DeleteToken(); err != nil {
		t.Fatalf("DeleteToken (keyring fails, file succeeds): %v", err)
	}

	_, err = LoadToken()
	if err == nil {
		t.Fatal("expected error loading token after deletion")
	}
}

func TestDeleteToken_TokenInKeyring_FileMissing(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	token := "keyring-only-token"
	if err := SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	cfgDir, _ := config.GetConfigDir()
	_ = os.Remove(filepath.Join(cfgDir, tokenCacheFile))

	loaded, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken before delete: %v", err)
	}
	if loaded != token {
		t.Fatalf("got %q, want %q", loaded, token)
	}

	if err := DeleteToken(); err != nil {
		t.Fatalf("DeleteToken (keyring succeeds, file missing): %v", err)
	}

	_, err = LoadToken()
	if err == nil {
		t.Fatal("expected error loading token after deletion")
	}
}

func TestDeleteToken_BothFail_ReturnsError(t *testing.T) {
	keyring.MockInitWithError(errNoKeyring)
	dir := t.TempDir()

	// Save a token to file first.
	t.Setenv("HOME", dir)
	token := "both-fail-token"
	if err := SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	// Wipe HOME so GetConfigDir fails → deleteFromFile also fails.
	t.Setenv("HOME", "")

	err := DeleteToken()
	if err == nil {
		t.Fatal("expected error when both keyring and file deletion fail")
	}
}

func TestDeleteToken_Idempotent(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	token := "idempotent-token"
	if err := SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	if err := DeleteToken(); err != nil {
		t.Fatalf("first DeleteToken: %v", err)
	}

	if err := DeleteToken(); err != nil {
		t.Fatalf("second DeleteToken (idempotent): %v", err)
	}
}

// ---------------------------------------------------------------------------
// SaveToken
// ---------------------------------------------------------------------------

func TestSaveToken_KeyringAvailable_SavesToKeyring(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	token := "save-keyring-token"
	if err := SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	loaded, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if loaded != token {
		t.Fatalf("got %q, want %q", loaded, token)
	}

	cfgDir, _ := config.GetConfigDir()
	if _, err := os.Stat(filepath.Join(cfgDir, tokenCacheFile)); err == nil {
		t.Fatal("expected no token file when keyring was used")
	}
}

func TestSaveToken_KeyringFails_FallsBackToFile(t *testing.T) {
	keyring.MockInitWithError(errNoKeyring)
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	token := "save-file-token"
	if err := SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	loaded, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if loaded != token {
		t.Fatalf("got %q, want %q", loaded, token)
	}
}

func TestSaveToken_KeyringSucceeds_FileCleanupFails(t *testing.T) {
	// Plant a token file directly, then verify SaveToken with a working
	// keyring still succeeds (best-effort file cleanup failure is a warning).
	keyring.MockInitWithError(errNoKeyring)
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	legacy := "legacy-file-token"
	if err := saveToFile(legacy); err != nil {
		t.Fatalf("saveToFile: %v", err)
	}

	// Switch to a working keyring. SaveToken should try and fail to clean
	// up the file (stale file), but still succeed overall.
	keyring.MockInit()
	token2 := "second-token"
	if err := SaveToken(token2); err != nil {
		t.Fatalf("SaveToken with keyring OK but file cleanup blocked: %v", err)
	}

	loaded, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if loaded != token2 {
		t.Fatalf("got %q, want %q", loaded, token2)
	}
}

// ---------------------------------------------------------------------------
// LoadToken
// ---------------------------------------------------------------------------

func TestLoadToken_NoToken_ReturnsError(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, err := LoadToken()
	if err == nil {
		t.Fatal("expected error when no token exists")
	}
}

func TestLoadToken_EmptyTokenInKeyring_FallsToFile(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := keyring.Set(keyringService, keyringUser, ""); err != nil {
		t.Fatalf("keyring.Set empty: %v", err)
	}

	_, err := LoadToken()
	if err == nil {
		t.Fatal("expected error when keyring has empty token and no file")
	}
}

func TestLoadToken_EmptyTokenInKeyring_TokenInFile_ReturnsFileToken(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := keyring.Set(keyringService, keyringUser, ""); err != nil {
		t.Fatalf("keyring.Set empty: %v", err)
	}

	token := "file-token"
	if err := saveToFile(token); err != nil {
		t.Fatalf("saveToFile: %v", err)
	}

	loaded, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if loaded != token {
		t.Fatalf("got %q, want %q", loaded, token)
	}
}

func TestLoadToken_KeyringTokenTakesPriority(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	krToken := "keyring-token"
	if err := keyring.Set(keyringService, keyringUser, krToken); err != nil {
		t.Fatalf("keyring.Set: %v", err)
	}

	fileToken := "file-token"
	if err := saveToFile(fileToken); err != nil {
		t.Fatalf("saveToFile: %v", err)
	}

	loaded, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if loaded != krToken {
		t.Fatalf("got %q, want %q", loaded, krToken)
	}
}

func TestLoadToken_CorruptFile_ReturnsError(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfgDir, _ := config.GetConfigDir()
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	fp := filepath.Join(cfgDir, tokenCacheFile)
	if err := os.WriteFile(fp, []byte("{invalid json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadToken()
	if err == nil {
		t.Fatal("expected error with corrupt token file")
	}
}

// ---------------------------------------------------------------------------
// Save → Load round-trips
// ---------------------------------------------------------------------------

func TestSaveLoadRoundtrip_Keyring(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	token := "roundtrip-kr"
	if err := SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	loaded, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if loaded != token {
		t.Fatalf("got %q, want %q", loaded, token)
	}
}

func TestSaveLoadRoundtrip_File(t *testing.T) {
	keyring.MockInitWithError(errNoKeyring)
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	token := "roundtrip-file"
	if err := SaveToken(token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	loaded, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if loaded != token {
		t.Fatalf("got %q, want %q", loaded, token)
	}
}
