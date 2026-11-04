package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
)

var ErrConfigNotFound = errors.New("configuration not found - please run 'flotte bootstrap <server-url>' first")

type ClientConfig struct {
	FlotteUrl string `json:"flotteUrl"`
}

func NewConfig() *ClientConfig {
	return &ClientConfig{}
}

func LoadConfig() (*ClientConfig, error) {
	path, err := GetStoragePath()
	if err != nil {
		return nil, fmt.Errorf("error getting setting path: %w", err)
	}

	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		return nil, err
	}

	file, err := os.Open(path) // #nosec G304 file is checked above
	if err != nil {
		return nil, fmt.Errorf("error opening config file: %w", err)
	}
	defer file.Close()

	var config ClientConfig
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return nil, fmt.Errorf("error decoding config file: %w", err)
	}
	return &config, nil
}

func LoadOrCreate() (*ClientConfig, error) {
	cfg, err := LoadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrConfigNotFound
		}
		return nil, err
	}

	if cfg.FlotteUrl == "" {
		return nil, ErrConfigNotFound
	}

	return cfg, nil
}

func (c *ClientConfig) Save() error {
	path, err := EnsureStoragePath()
	if err != nil {
		return fmt.Errorf("error ensuring config path: %w", err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, storageFilePermissions) // #nosec G304 opening existing file with secure permissions
	if err != nil {
		return fmt.Errorf("error opening config file for writing: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(c); err != nil {
		return fmt.Errorf("error encoding config to file: %w", err)
	}

	return nil
}

func GetConfigDir() (string, error) {
	p, err := GetStoragePath()
	if err != nil {
		return "", err
	}
	return path.Dir(p), nil
}
