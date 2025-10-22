package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"sshwebdoor/config"
)

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install sshwebdoor as a systemd service",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath := cmd.Flag("config").Value.String()
			if cfgPath == "" {
				cfgPath = config.DefaultPath
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			destination := "/usr/local/bin/sshwebdoor"
			if err := copyFile(exe, destination, 0o755); err != nil {
				return fmt.Errorf("copy binary: %w", err)
			}

			if err := ensureServiceUser(); err != nil {
				return err
			}

			unit := buildUnitFile(cfgPath)
			if err := os.WriteFile("/etc/systemd/system/sshwebdoor.service", []byte(unit), 0o644); err != nil {
				return fmt.Errorf("write unit file: %w", err)
			}

			if err := runCommand("systemctl", "daemon-reload"); err != nil {
				return err
			}
			if err := runCommand("systemctl", "enable", "sshwebdoor"); err != nil {
				return err
			}
			if err := runCommand("systemctl", "start", "sshwebdoor"); err != nil {
				return err
			}

			fmt.Println("sshwebdoor installed and started via systemd")
			return nil
		},
	}
	return cmd
}

func copyFile(src, dst string, mode os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}
	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func ensureServiceUser() error {
	if err := runCommand("id", "-u", "sshwebdoor"); err == nil {
		return nil
	}
	if err := runCommand("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "sshwebdoor"); err != nil {
		return fmt.Errorf("create service user: %w", err)
	}
	return nil
}

func buildUnitFile(cfgPath string) string {
	return fmt.Sprintf(`[Unit]
Description=sshwebdoor single-port SSH/HTTPS gateway
After=network.target %s

[Service]
User=sshwebdoor
Group=sshwebdoor
ExecStart=/usr/local/bin/sshwebdoor serve --config %s
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`, detectSSHServiceName(), cfgPath)
}

func detectSSHServiceName() string {
	if _, err := os.Stat("/lib/systemd/system/ssh.service"); err == nil {
		return "ssh.service"
	}
	return "sshd.service"
}
