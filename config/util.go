package config

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
)

// New produces a new config object by parsing
// the default configuration for the values.
func New() (*Config, error) {
	cfg := new(Config)

	cfgFile, err := findFile("tyk.conf")
	if err != nil {
		// Return cfg filled with environment
		// if we don't have a config file.
		if errors.Is(err, os.ErrNotExist) {
			err := FillEnv(cfg)
			return cfg, err
		}

		return nil, err
	}

	if err := Load([]string{cfgFile}, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// NewDefaultWithEnv gives a deep clone of the Default configuration and
// fills it from environment provided.
func NewDefaultWithEnv() (*Config, error) {
	cfg := new(Config)

	b, err := json.Marshal(Default)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, err
	}

	if err := FillEnv(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func findFile(filename string) (string, error) {
	// Get folder in which current file lives
	_, testFile, _, _ := runtime.Caller(0)
	// Strip the filename and produce the dir
	currentDir := path.Dir(testFile)

	// Traverse the current directory and its parent directories
	for {
		// Check if the file exists in the current directory
		filePath := filepath.Join(currentDir, filename)
		_, err := os.Stat(filePath)
		if err == nil {
			// File found
			return filePath, nil
		}

		// Move to the parent directory
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			// No more parent directories remaining
			break
		}

		currentDir = parentDir
	}

	// File not found
	return "", os.ErrNotExist
}

// HostAddrs returns a sanitized list of hosts to connect to.
func (config *StorageOptionsConf) HostAddrs() (addrs []string) {
	if len(config.Addrs) != 0 {
		addrs = config.Addrs
	} else {
		for h, p := range config.Hosts {
			addr := h + ":" + p
			addrs = append(addrs, addr)
		}
	}

	if len(addrs) == 0 && config.Port != 0 {
		addr := config.Host + ":" + strconv.Itoa(config.Port)
		addrs = append(addrs, addr)
	}

	return addrs
}
