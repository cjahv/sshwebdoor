package system

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
)

const (
	ServiceUser  = "sshwebdoor"
	ServiceGroup = "sshwebdoor"
	BinaryPath   = "/usr/local/bin/sshwebdoor"
	UnitPath     = "/etc/systemd/system/sshwebdoor.service"
	ConfigDir    = "/etc/sshwebdoor"
	LogDir       = "/var/log/sshwebdoor"
)

// CopyFile copies a binary to the destination path with the provided permissions.
func CopyFile(src, dst string, perm os.FileMode) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".sshwebdoor-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := io.Copy(tmp, input); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// EnsureServiceAccount creates the service user and group when absent.
func EnsureServiceAccount() error {
	if _, err := user.Lookup(ServiceUser); err == nil {
		return nil
	}
	if err := exec.Command("groupadd", "-f", ServiceGroup).Run(); err != nil {
		return fmt.Errorf("groupadd %s: %w", ServiceGroup, err)
	}
	cmd := exec.Command("useradd", "-r", "-M", "-s", "/usr/sbin/nologin", "-g", ServiceGroup, ServiceUser)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("useradd %s: %w", ServiceUser, err)
	}
	return nil
}

// WriteUnitFile writes the systemd unit file referencing the provided config path.
func WriteUnitFile(configPath string) error {
	content := fmt.Sprintf(`[Unit]
Description=sshwebdoor single-port SSH/HTTPS gateway
After=network.target ssh.service

[Service]
User=%s
Group=%s
ExecStart=%s serve --config %s
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, ServiceUser, ServiceGroup, BinaryPath, configPath)

	if err := os.WriteFile(UnitPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	return nil
}

// RunSystemctl executes systemctl commands.
func RunSystemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ReloadSSHD attempts to reload the OpenSSH daemon using systemctl.
func ReloadSSHD() error {
	if err := RunSystemctl("reload", "sshd"); err == nil {
		return nil
	}
	return RunSystemctl("reload", "ssh")
}
