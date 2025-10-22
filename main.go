package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"sshwebdoor/internal/config"
	"sshwebdoor/internal/daemon"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "serve":
		serveCmd(os.Args[2:])
	case "init":
		if err := runInit(config.DefaultConfigPath); err != nil {
			log.Fatalf("init failed: %v", err)
		}
	case "install":
		if err := runInstall(config.DefaultConfigPath); err != nil {
			log.Fatalf("install failed: %v", err)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <serve|init|install>\n", filepath.Base(os.Args[0]))
}

func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "path to configuration file")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("failed to parse serve flags: %v", err)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load configuration: %v", err)
	}

	srv, err := daemon.NewServer(cfg, log.Default())
	if err != nil {
		log.Fatalf("create server: %v", err)
	}

	ctx, stop := signalContext()
	defer stop()

	if err := srv.Serve(ctx); err != nil {
		log.Fatalf("server terminated: %v", err)
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signalNotify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()
	return ctx, cancel
}

func signalNotify(c chan<- os.Signal, sig ...os.Signal) {
	signal.Notify(c, sig...)
}

func runInit(cfgPath string) error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Listening address [%s]: ", config.Default().ListenAddress)
	listenAddr, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read listen address: %w", err)
	}
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		listenAddr = config.Default().ListenAddress
	}

	fmt.Print("Forward SSH target [127.0.0.1:22]: ")
	forward, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read ssh target: %w", err)
	}
	forward = strings.TrimSpace(forward)
	if forward == "" {
		forward = "127.0.0.1:22"
	}

	restrict, err := promptYesNo(reader, "Restrict OpenSSH to loopback only? [y/N]: ")
	if err != nil {
		return err
	}

	passwordHash, err := promptPassword()
	if err != nil {
		return err
	}

	cfg := config.Default()
	cfg.ListenAddress = listenAddr
	cfg.SSHForward = forward
	if restrict {
		cfg.SSHMode = "loopback"
	} else {
		cfg.SSHMode = "unchanged"
	}
	cfg.PasswordHash = passwordHash

	if err := ensureTLSMaterial(cfg); err != nil {
		return err
	}

	if err := config.Save(cfg, cfgPath); err != nil {
		return err
	}

	fmt.Printf("Configuration written to %s\n", cfgPath)

	if restrict {
		if err := applySSHLoopback(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to restrict sshd to loopback: %v\n", err)
		} else {
			fmt.Println("sshd configured to listen on loopback only.")
		}
	}

	return nil
}

func ensureTLSMaterial(cfg *config.Config) error {
	if config.Exists(cfg.TLSCertPath) && config.Exists(cfg.TLSKeyPath) {
		return nil
	}
	fmt.Println("Generating self-signed TLS certificate...")
	if err := generateSelfSignedCertificate(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil {
		return fmt.Errorf("generate certificate: %w", err)
	}
	return nil
}

func promptYesNo(reader *bufio.Reader, prompt string) (bool, error) {
	fmt.Print(prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes", nil
}

func promptPassword() (string, error) {
	fmt.Print("Security password: ")
	pass1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	fmt.Print("Confirm password: ")
	pass2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("read password confirmation: %w", err)
	}
	if !bytes.Equal(pass1, pass2) {
		return "", errors.New("passwords do not match")
	}
	hash, err := bcrypt.GenerateFromPassword(pass1, bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

func generateSelfSignedCertificate(certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		return err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sshwebdoor"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}
	return nil
}

func runInstall(cfgPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determine executable path: %w", err)
	}
	targetPath := "/usr/local/bin/sshwebdoor"
	if err := copyFile(exePath, targetPath); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := os.Chmod(targetPath, 0o755); err != nil {
		return fmt.Errorf("chmod target: %w", err)
	}

	service := buildServiceUnit(cfgPath)
	if err := os.WriteFile("/etc/systemd/system/sshwebdoor.service", []byte(service), 0o644); err != nil {
		return fmt.Errorf("write service unit: %w", err)
	}

	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "sshwebdoor"},
		{"systemctl", "start", "sshwebdoor"},
	}
	for _, cmd := range cmds {
		if err := runCommand(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}
	fmt.Println("sshwebdoor service installed and started.")
	return nil
}

func buildServiceUnit(cfgPath string) string {
	return fmt.Sprintf(`[Unit]
Description=sshwebdoor single-port SSH/HTTPS gateway
After=network.target ssh.service sshd.service

[Service]
ExecStart=/usr/local/bin/sshwebdoor serve --config %s
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`, cfgPath)
}

func copyFile(src, dst string) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	output, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer output.Close()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func applySSHLoopback() error {
	snippet := "# Managed by sshwebdoor\nListenAddress 127.0.0.1\n"
	configDir := "/etc/ssh/sshd_config.d"
	if info, err := os.Stat(configDir); err == nil && info.IsDir() {
		path := filepath.Join(configDir, "sshwebdoor.conf")
		if err := os.WriteFile(path, []byte(snippet), 0o644); err != nil {
			return err
		}
	} else {
		path := "/etc/ssh/sshd_config"
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.WriteString("\n" + snippet); err != nil {
			return err
		}
	}
	if err := runCommand("systemctl", "reload", "sshd"); err != nil {
		if err := runCommand("systemctl", "reload", "ssh"); err != nil {
			return err
		}
	}
	return nil
}
