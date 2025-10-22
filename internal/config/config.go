package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultConfigPath is the canonical location for the sshwebdoor configuration file.
	DefaultConfigPath = "/etc/sshwebdoor/config.yaml"
	// DefaultCertPath is the default path for the TLS certificate generated during init.
	DefaultCertPath = "/etc/sshwebdoor/tls.crt"
	// DefaultKeyPath is the default path for the TLS private key generated during init.
	DefaultKeyPath = "/etc/sshwebdoor/tls.key"
)

// Config encapsulates the runtime settings for the daemon.
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

// Default returns a configuration struct populated with sensible defaults.
func Default() *Config {
	return &Config{
		ListenAddress:        "0.0.0.0:8443",
		SSHForward:           "127.0.0.1:22",
		MaxAttempts:          3,
		LockoutSeconds:       60,
		AttemptWindowSeconds: 300,
		SSHMode:              "unchanged",
		TLSCertPath:          DefaultCertPath,
		TLSKeyPath:           DefaultKeyPath,
	}
}

// EnsureDefaults populates unset optional fields with default values.
func (c *Config) EnsureDefaults() {
	defaults := Default()
	if c.ListenAddress == "" {
		c.ListenAddress = defaults.ListenAddress
	}
	if c.SSHForward == "" {
		c.SSHForward = defaults.SSHForward
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaults.MaxAttempts
	}
	if c.LockoutSeconds <= 0 {
		c.LockoutSeconds = defaults.LockoutSeconds
	}
	if c.AttemptWindowSeconds <= 0 {
		c.AttemptWindowSeconds = defaults.AttemptWindowSeconds
	}
	if c.SSHMode == "" {
		c.SSHMode = defaults.SSHMode
	}
	if c.TLSCertPath == "" {
		c.TLSCertPath = defaults.TLSCertPath
	}
	if c.TLSKeyPath == "" {
		c.TLSKeyPath = defaults.TLSKeyPath
	}
}

// Load reads configuration data from the provided path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	cfg.EnsureDefaults()
	if cfg.PasswordHash == "" {
		return nil, errors.New("configuration missing password_hash")
	}
	return cfg, nil
}

// Save persists the configuration to disk with secure permissions.
func Save(cfg *Config, path string) error {
	cfg.EnsureDefaults()
	if cfg.PasswordHash == "" {
		return errors.New("password hash must be set before saving configuration")
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// TouchLockFile is a helper that ensures the configuration directory exists with strict permissions.
func TouchLockFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	return nil
}

// FileMTime returns the modification time of the given file if it exists.
func FileMTime(path string) (time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// Exists reports whether the provided path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// CopyPermissions ensures the file mode on the target matches the supplied mode if the file exists.
func CopyPermissions(path string, mode fs.FileMode) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
