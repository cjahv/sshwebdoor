package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultDir is the directory that stores configuration and TLS assets.
	DefaultDir = "/etc/sshwebdoor"
	// DefaultPath is the canonical configuration file path.
	DefaultPath = DefaultDir + "/config.yaml"
)

// Config encapsulates all user supplied settings for the daemon.
type Config struct {
	ListenAddress        string `yaml:"listen_address"`
	SSHForward           string `yaml:"ssh_forward"`
	PasswordHash         string `yaml:"password_hash"`
	MaxAttempts          int    `yaml:"max_attempts"`
	LockoutSeconds       int    `yaml:"lockout_seconds"`
	AttemptWindowSeconds int    `yaml:"attempt_window_seconds"`
	SSHMode              string `yaml:"ssh_mode"`
	CertFile             string `yaml:"cert_file"`
	KeyFile              string `yaml:"key_file"`
}

// Default returns the baseline configuration populated with sensible defaults.
func Default() Config {
	return Config{
		ListenAddress:        "0.0.0.0:8443",
		SSHForward:           "127.0.0.1:22",
		MaxAttempts:          3,
		LockoutSeconds:       60,
		AttemptWindowSeconds: 300,
		SSHMode:              "unchanged",
		CertFile:             DefaultDir + "/server.crt",
		KeyFile:              DefaultDir + "/server.key",
	}
}

// Load reads the YAML configuration from the given path.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Save persists the configuration to disk, creating the parent directory as needed.
func (c Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}

	data, err := yaml.Marshal(&c)
	if err != nil {
		return err
	}

	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0o640); err != nil {
		return err
	}
	if err := os.Chmod(temp, 0o640); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

// Exists reports whether a configuration file already exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// EnsureDir makes sure the base directory exists.
func EnsureDir() error {
	return os.MkdirAll(DefaultDir, 0o750)
}

// CopyIfNotExists copies a file into the configuration directory if it does not yet exist.
func CopyIfNotExists(src, dst string, perm fs.FileMode) error {
	if _, err := os.Stat(dst); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	if err := os.WriteFile(dst, input, perm); err != nil {
		return err
	}
	return nil
}
