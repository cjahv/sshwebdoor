package cli

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"sshwebdoor/internal/config"
)

func newInitCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Run the interactive initialization wizard",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(cmd)
		},
	}
}

func runInit(cmd *cobra.Command) error {
	if err := config.EnsureDir(); err != nil {
		return fmt.Errorf("ensure config directory: %w", err)
	}

	reader := bufio.NewReader(cmd.InOrStdin())
	cfg := config.Default()

	if config.Exists(config.DefaultPath) {
		overwrite, err := promptString(cmd, reader, "Configuration already exists. Overwrite? (y/N)", "N")
		if err != nil {
			return err
		}
		if strings.ToLower(overwrite) != "y" {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborting without changes.")
			return nil
		}
	}

	if addr, err := promptString(cmd, reader, fmt.Sprintf("Listen address"), cfg.ListenAddress); err != nil {
		return err
	} else {
		cfg.ListenAddress = addr
	}

	if forward, err := promptString(cmd, reader, "SSH forward address", cfg.SSHForward); err != nil {
		return err
	} else {
		cfg.SSHForward = forward
	}

	pwd, err := promptPassword(cmd, "Set web password: ")
	if err != nil {
		return err
	}
	if pwd == "" {
		return errors.New("password cannot be empty")
	}

	confirm, err := promptPassword(cmd, "Confirm password: ")
	if err != nil {
		return err
	}
	if pwd != confirm {
		return errors.New("passwords do not match")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	cfg.PasswordHash = string(hash)

	restrict, err := promptString(cmd, reader, "Restrict OpenSSH to loopback only? (y/N)", "N")
	if err != nil {
		return err
	}
	if strings.ToLower(restrict) == "y" {
		cfg.SSHMode = "loopback"
		if err := restrictOpenSSH(cmd, cfg.SSHForward); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to adjust sshd configuration: %v\n", err)
		}
	} else {
		cfg.SSHMode = "unchanged"
	}

	if err := ensureCertificate(cmd, cfg); err != nil {
		return err
	}

	if err := cfg.Save(config.DefaultPath); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Configuration written to %s\n", config.DefaultPath)
	return nil
}

func promptString(cmd *cobra.Command, reader *bufio.Reader, prompt, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "%s [%s]: ", prompt, def)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "%s: ", prompt)
	}
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return def, nil
	}
	return trimmed, nil
}

func promptPassword(cmd *cobra.Command, prompt string) (string, error) {
	if f, ok := cmd.InOrStdin().(*os.File); ok {
		fmt.Fprint(cmd.OutOrStdout(), prompt)
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(cmd.OutOrStdout())
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}

	reader := bufio.NewReader(cmd.InOrStdin())
	fmt.Fprint(cmd.OutOrStdout(), prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

func ensureCertificate(cmd *cobra.Command, cfg config.Config) error {
	// If files exist, do nothing.
	if _, err := os.Stat(cfg.CertFile); err == nil {
		if _, err := os.Stat(cfg.KeyFile); err == nil {
			return nil
		}
	}

	host, _, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		host = "localhost"
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "sshwebdoor"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.CertFile), 0o750); err != nil {
		return err
	}

	certOut, err := os.Create(cfg.CertFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(cfg.KeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Generated self-signed certificate at %s\n", cfg.CertFile)
	return nil
}

func restrictOpenSSH(cmd *cobra.Command, forward string) error {
	host, port, err := net.SplitHostPort(forward)
	if err != nil {
		return fmt.Errorf("parse forward address: %w", err)
	}
	_ = host // currently unused but kept for future logic

	snippet := "# Managed by sshwebdoor\nListenAddress 127.0.0.1\nPort " + port + "\n"

	dir := "/etc/ssh/sshd_config.d"
	if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
		path := filepath.Join(dir, "sshwebdoor.conf")
		if err := os.WriteFile(path, []byte(snippet), 0o640); err != nil {
			return err
		}
	} else {
		path := filepath.Join(config.DefaultDir, "sshd_config_snippet.conf")
		if err := os.WriteFile(path, []byte(snippet), 0o640); err != nil {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "sshd_config.d not found; wrote snippet to %s. Merge manually.\n", path)
		return nil
	}

	serviceNames := []string{"sshd", "ssh"}
	for _, svc := range serviceNames {
		if err := exec.Command("systemctl", "reload", svc).Run(); err == nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Reloaded %s service\n", svc)
			return nil
		}
	}

	return errors.New("unable to reload sshd via systemctl")
}
