package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func Execute(version string) {
	rootCmd := &cobra.Command{
		Use:   "sshwebdoor",
		Short: "Single-port SSH/HTTPS gateway",
	}

	rootCmd.PersistentFlags().StringP("config", "c", "", "path to config file (default: /etc/sshwebdoor/config.yaml)")

	rootCmd.AddCommand(newInitCmd())
	rootCmd.AddCommand(newInstallCmd())
	rootCmd.AddCommand(newServeCmd())
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
