package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"sshwebdoor/internal/config"
)

const systemdUnitPath = "/etc/systemd/system/sshwebdoor.service"

func newInstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install sshwebdoor as a systemd service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(cmd)
		},
	}
}

func runInstall(cmd *cobra.Command) error {
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}

	target := "/usr/local/bin/sshwebdoor"
	if err := copyFile(binPath, target, 0o755); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Installed binary to %s\n", target)

	if err := writeUnitFile(cmd.OutOrStdout()); err != nil {
		return err
	}

	if err := ensureServiceAccount(cmd); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to ensure service account: %v\n", err)
	}

	if err := config.EnsureDir(); err != nil {
		return err
	}

	reload := exec.Command("systemctl", "daemon-reload")
	if err := reload.Run(); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to reload systemd: %v\n", err)
	}

	enable := exec.Command("systemctl", "enable", "sshwebdoor")
	if err := enable.Run(); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to enable service: %v\n", err)
	}

	start := exec.Command("systemctl", "start", "sshwebdoor")
	if err := start.Run(); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to start service: %v\n", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Installation complete. Use 'systemctl status sshwebdoor' to verify.")
	return nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}

	return os.Rename(tmp, dst)
}

func ensureServiceAccount(cmd *cobra.Command) error {
	if err := exec.Command("id", "-u", "sshwebdoor").Run(); err == nil {
		return nil
	}

	args := []string{"--system", "--create-home", "--home-dir", "/var/lib/sshwebdoor", "--shell", "/usr/sbin/nologin", "sshwebdoor"}
	if err := exec.Command("useradd", args...).Run(); err != nil {
		return err
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Created system user sshwebdoor")
	return nil
}

func writeUnitFile(stdout io.Writer) error {
	const unit = `[Unit]
Description=sshwebdoor single-port gateway
After=network.target ssh.service

[Service]
ExecStart=/usr/local/bin/sshwebdoor serve --config /etc/sshwebdoor/config.yaml
Restart=on-failure
User=sshwebdoor
Group=sshwebdoor
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`

	if err := os.WriteFile(systemdUnitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	fmt.Fprintf(stdout, "Wrote systemd unit to %s\n", systemdUnitPath)
	return nil
}
