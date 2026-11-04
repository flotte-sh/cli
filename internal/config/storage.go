package config

import (
	"os"
	"path"
)

const configPath = ".flotte"
const configFileName = "config.json"

const storageFilePermissions = 0600

func GetStoragePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return path.Join(home, configPath, configFileName), nil
}

func EnsureStoragePath() (string, error) {
	dir, err := GetStoragePath()
	if err != nil {
		return "", err
	}

	err = os.MkdirAll(path.Dir(dir), 0700)
	if err != nil {
		return "", err
	}

	_, err = os.Stat(dir)
	if os.IsNotExist(err) {
		file, err := os.OpenFile(dir, os.O_RDONLY|os.O_CREATE, storageFilePermissions) // #nosec G304 create empty file with secure permissions
		if err != nil {
			return "", err
		}
		_ = file.Close()
	}

	return dir, nil
}
