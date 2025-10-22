package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const DefaultPath = "/etc/sshwebdoor/config.yaml"

// Config captures runtime configuration for sshwebdoor.
type Config struct {
	ListenAddress        string `yaml:"listen_address"`
	SSHForward           string `yaml:"ssh_forward"`
	PasswordHash         string `yaml:"password_hash"`
	MaxAttempts          int    `yaml:"max_attempts"`
	LockoutSeconds       int    `yaml:"lockout_seconds"`
	AttemptWindowSeconds int    `yaml:"attempt_window_seconds"`
	SSHMode              string `yaml:"ssh_mode"`
}

func Default() Config {
	return Config{
		ListenAddress:        "0.0.0.0:8443",
		SSHForward:           "127.0.0.1:22",
		MaxAttempts:          3,
		LockoutSeconds:       60,
		AttemptWindowSeconds: 300,
		SSHMode:              "unchanged",
	}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	if cfg.ListenAddress == "" {
		return errors.New("listen_address must be set")
	}
	if cfg.SSHForward == "" {
		return errors.New("ssh_forward must be set")
	}
	if cfg.PasswordHash == "" {
		return errors.New("password_hash must be set")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// EnsureReadable attempts to set permissions on the config directory so only
// the owner and group can read it.
func EnsureReadable(path string) error {
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o750); err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			return nil
		}
		return err
	}
	return nil
}
