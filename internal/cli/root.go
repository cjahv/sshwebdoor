package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is updated at build time via -ldflags if desired.
var Version = "dev"

// NewRootCommand constructs the base command tree.
func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sshwebdoor",
		Short: "Single-port HTTPS/SSH gateway and web door",
		Long:  "sshwebdoor multiplexes HTTPS and SSH traffic over a single TCP port and provides a password-protected landing page.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "sshwebdoor %s\n", Version)
			return nil
		},
		SilenceUsage: true,
	}

	cmd.AddCommand(newInitCommand())
	cmd.AddCommand(newServeCommand())
	cmd.AddCommand(newInstallCommand())
	cmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), Version)
		},
	})

	return cmd
}
