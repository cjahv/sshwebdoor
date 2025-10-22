package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"

	"sshwebdoor/config"
	"sshwebdoor/internal/server"
)

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize sshwebdoor configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath := cmd.Flag("config").Value.String()
			if cfgPath == "" {
				cfgPath = config.DefaultPath
			}
			reader := bufio.NewReader(os.Stdin)
			cfg := config.Default()

			fmt.Printf("Listening address [%s]: ", cfg.ListenAddress)
			listen, _ := reader.ReadString('\n')
			listen = strings.TrimSpace(listen)
			if listen != "" {
				cfg.ListenAddress = listen
			}

			fmt.Printf("SSH forward target [%s]: ", cfg.SSHForward)
			forward, _ := reader.ReadString('\n')
			forward = strings.TrimSpace(forward)
			if forward != "" {
				cfg.SSHForward = forward
			}

			passwordHash, err := promptPassword(reader)
			if err != nil {
				return err
			}
			cfg.PasswordHash = passwordHash

			fmt.Printf("Restrict OpenSSH to loopback? (y/N): ")
			restrict, _ := reader.ReadString('\n')
			restrict = strings.TrimSpace(strings.ToLower(restrict))
			if restrict == "y" || restrict == "yes" {
				if err := server.ConfigureSSHLoopback(); err != nil {
					return fmt.Errorf("configure ssh loopback: %w", err)
				}
				cfg.SSHMode = "loopback"
			} else {
				cfg.SSHMode = "unchanged"
			}

			if err := config.Save(cfgPath, cfg); err != nil {
				return err
			}
			if err := config.EnsureReadable(cfgPath); err != nil {
				return err
			}

			fmt.Printf("Configuration written to %s\n", cfgPath)
			return nil
		},
	}
	return cmd
}

func promptPassword(reader *bufio.Reader) (string, error) {
	fmt.Print("Set web password: ")
	pass1, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	pass1 = strings.TrimSpace(pass1)
	fmt.Print("Confirm web password: ")
	pass2, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	pass2 = strings.TrimSpace(pass2)
	if pass1 == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	if pass1 != pass2 {
		return "", fmt.Errorf("passwords do not match")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass1), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
