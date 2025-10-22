package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"sshwebdoor/internal/config"
	"sshwebdoor/internal/server"
	"sshwebdoor/internal/system"
)

var (
	cfgPath string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sshwebdoor",
		Short: "Single-port HTTPS/SSH gateway",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", config.DefaultConfigPath, "Path to configuration file")

	rootCmd.AddCommand(newInitCommand(), newInstallCommand(), newServeCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func newInitCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize configuration and optional SSH restrictions",
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Geteuid() != 0 {
				return errors.New("init must be run as root")
			}
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Initializing sshwebdoor configuration at %s\n", cfgPath)

			defaults := config.Default()
			listen, err := promptString(reader, fmt.Sprintf("Listening address [%s]: ", defaults.ListenAddress), defaults.ListenAddress)
			if err != nil {
				return err
			}
			forward, err := promptString(reader, fmt.Sprintf("SSH forward target [%s]: ", defaults.SSHForward), defaults.SSHForward)
			if err != nil {
				return err
			}

			restrictAnswer, err := promptString(reader, "Restrict OpenSSH to loopback? [y/N]: ", "n")
			if err != nil {
				return err
			}
			restrict := strings.ToLower(strings.TrimSpace(restrictAnswer)) == "y"

			password, err := promptPassword("Set administrator password: ")
			if err != nil {
				return err
			}
			confirm, err := promptPassword("Confirm password: ")
			if err != nil {
				return err
			}
			if password != confirm {
				return errors.New("passwords do not match")
			}

			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("hash password: %w", err)
			}

			certDir := filepath.Join(filepath.Dir(cfgPath), "certs")
			if err := os.MkdirAll(certDir, 0o750); err != nil {
				return fmt.Errorf("create cert directory: %w", err)
			}
			certPath := filepath.Join(certDir, "server.crt")
			keyPath := filepath.Join(certDir, "server.key")
			if err := ensureCertificate(certPath, keyPath, listen); err != nil {
				return err
			}

			cfg := config.Config{
				ListenAddress:        listen,
				SSHForward:           forward,
				PasswordHash:         string(hash),
				MaxAttempts:          defaults.MaxAttempts,
				LockoutSeconds:       defaults.LockoutSeconds,
				AttemptWindowSeconds: defaults.AttemptWindowSeconds,
				SSHMode:              "unchanged",
				TLSCertPath:          certPath,
				TLSKeyPath:           keyPath,
			}
			if restrict {
				cfg.SSHMode = "loopback"
				if err := system.RestrictSSHToLoopback(); err != nil {
					return fmt.Errorf("restrict ssh: %w", err)
				}
				if err := system.ReloadSSHD(); err != nil {
					fmt.Printf("warning: failed to reload sshd: %v\n", err)
				}
			} else {
				if err := system.RemoveSSHRestriction(); err != nil {
					fmt.Printf("warning: failed to remove ssh restriction: %v\n", err)
				}
			}

			if err := config.Save(cfgPath, cfg); err != nil {
				return err
			}
			fmt.Printf("Configuration written to %s\n", cfgPath)
			return nil
		},
	}
}

func newInstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install the binary and register the systemd service",
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Geteuid() != 0 {
				return errors.New("install must be run as root")
			}
			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolve executable: %w", err)
			}
			if err := system.CopyFile(exe, system.BinaryPath, 0o755); err != nil {
				return fmt.Errorf("copy binary: %w", err)
			}
			if err := system.EnsureServiceAccount(); err != nil {
				return err
			}
			if err := os.MkdirAll(system.ConfigDir, 0o750); err != nil {
				return err
			}
			if err := os.MkdirAll(system.LogDir, 0o750); err != nil {
				return err
			}
			if err := ensureOwnership(system.ConfigDir); err != nil {
				fmt.Printf("warning: failed to set ownership on %s: %v\n", system.ConfigDir, err)
			}
			if err := ensureOwnership(system.LogDir); err != nil {
				fmt.Printf("warning: failed to set ownership on %s: %v\n", system.LogDir, err)
			}
			if err := ensureOwnership(cfgPath); err != nil {
				fmt.Printf("warning: failed to set ownership on %s: %v\n", cfgPath, err)
			}
			if err := system.WriteUnitFile(cfgPath); err != nil {
				return err
			}
			if err := system.RunSystemctl("daemon-reload"); err != nil {
				return err
			}
			if err := system.RunSystemctl("enable", "--now", "sshwebdoor"); err != nil {
				return err
			}
			fmt.Println("sshwebdoor service installed and started.")
			return nil
		},
	}
}

func newServeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the sshwebdoor service",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			logger := log.New(os.Stdout, "sshwebdoor: ", log.LstdFlags)
			srv, err := server.New(cfg, logger)
			if err != nil {
				return err
			}
			ctx, stop := signalContext()
			defer stop()
			return srv.Serve(ctx)
		},
	}
}

func promptString(reader *bufio.Reader, prompt string, def string) (string, error) {
	fmt.Print(prompt)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	bytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func ensureCertificate(certPath, keyPath, listenAddr string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}
	fmt.Printf("Generating self-signed TLS certificate at %s\n", certPath)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = "localhost"
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "sshwebdoor"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	tmpl.DNSNames = []string{"localhost"}
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	} else if host != "" && host != "0.0.0.0" && host != "::" {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}
	return nil
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

func ensureOwnership(path string) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	u, err := user.Lookup(system.ServiceUser)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}
