package system

import (
	"errors"
	"os"
	"path/filepath"
)

const sshDropInPath = "/etc/ssh/sshd_config.d/sshwebdoor.conf"

// RestrictSSHToLoopback writes a drop-in configuration to bind sshd to localhost only.
func RestrictSSHToLoopback() error {
	if err := os.MkdirAll(filepath.Dir(sshDropInPath), 0o755); err != nil {
		return err
	}
	content := []byte("# Managed by sshwebdoor\nListenAddress 127.0.0.1\n")
	return os.WriteFile(sshDropInPath, content, 0o644)
}

// RemoveSSHRestriction removes the sshd drop-in if present.
func RemoveSSHRestriction() error {
	if err := os.Remove(sshDropInPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return nil
}
