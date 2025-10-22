package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath = "/etc/sshwebdoor/config.yaml"
)

// Config represents the persisted runtime configuration for the daemon.
type Config struct {
	ListenAddress        string `yaml:"listen_address"`
	SSHForward           string `yaml:"ssh_forward"`
	PasswordHash         string `yaml:"password_hash"`
	MaxAttempts          int    `yaml:"max_attempts"`
	LockoutSeconds       int    `yaml:"lockout_seconds"`
	AttemptWindowSeconds int    `yaml:"attempt_window_seconds"`
	SSHMode              string `yaml:"ssh_mode"`
	TLSCertPath          string `yaml:"tls_cert_path"`
	TLSKeyPath           string `yaml:"tls_key_path"`
}

// Default returns the recommended defaults for a fresh installation.
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

// ApplyDefaults ensures optional fields are populated with defaults where zero values were provided.
func (c *Config) ApplyDefaults() {
	defaults := Default()
	if c.ListenAddress == "" {
		c.ListenAddress = defaults.ListenAddress
	}
	if c.SSHForward == "" {
		c.SSHForward = defaults.SSHForward
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = defaults.MaxAttempts
	}
	if c.LockoutSeconds == 0 {
		c.LockoutSeconds = defaults.LockoutSeconds
	}
	if c.AttemptWindowSeconds == 0 {
		c.AttemptWindowSeconds = defaults.AttemptWindowSeconds
	}
	if c.SSHMode == "" {
		c.SSHMode = defaults.SSHMode
	}
}

// Validate performs a basic validation of the configuration.
func (c Config) Validate() error {
	if c.ListenAddress == "" {
		return errors.New("listen_address must be provided")
	}
	if c.SSHForward == "" {
		return errors.New("ssh_forward must be provided")
	}
	if c.PasswordHash == "" {
		return errors.New("password_hash must be provided")
	}
	if c.TLSCertPath == "" || c.TLSKeyPath == "" {
		return errors.New("tls_cert_path and tls_key_path must be provided")
	}
	if c.MaxAttempts <= 0 {
		return errors.New("max_attempts must be greater than 0")
	}
	if c.LockoutSeconds <= 0 {
		return errors.New("lockout_seconds must be greater than 0")
	}
	if c.AttemptWindowSeconds <= 0 {
		return errors.New("attempt_window_seconds must be greater than 0")
	}
	switch c.SSHMode {
	case "unchanged", "loopback":
	default:
		return fmt.Errorf("unknown ssh_mode %q", c.SSHMode)
	}
	return nil
}

// Load reads configuration from disk.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	cfg.ApplyDefaults()
	return cfg, nil
}

// Save writes the configuration to disk atomically.
func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	enc := yaml.NewEncoder(tmp)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		tmp.Close()
		return fmt.Errorf("encode config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("commit config file: %w", err)
	}
	return nil
}

// Exists reports whether the configuration file currently exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// EnsurePermissions ensures the config file has the requested permissions.
func EnsurePermissions(path string, perm fs.FileMode) error {
	return os.Chmod(path, perm)
}
