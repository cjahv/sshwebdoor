package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"sshwebdoor/config"
	"sshwebdoor/internal/server"
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the sshwebdoor gateway",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath := cmd.Flag("config").Value.String()
			if cfgPath == "" {
				cfgPath = config.DefaultPath
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			srv, err := server.New(cfg)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return srv.Serve(ctx)
		},
	}
	return cmd
}
