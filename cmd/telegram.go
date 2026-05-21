package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ba0f3/lunacli/internal/approval"
	"github.com/ba0f3/lunacli/internal/config"
	"github.com/spf13/cobra"
)

var telegramCmd = &cobra.Command{
	Use:   "telegram",
	Short: "Telegram approval integration",
}

var telegramPollCmd = &cobra.Command{
	Use:   "poll",
	Short: "Listen for Telegram Approve/Deny inline button callbacks",
	Long: `Long-polls Telegram getUpdates for callback_query events and applies approve/deny
to the local approvals database. Run alongside MCP serve when agents use execute_remote;
luna exec starts this automatically while waiting for approval.`,
	Run: func(cmd *cobra.Command, args []string) {
		settings, err := config.LoadSettings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "config: %v\n", err)
			os.Exit(1)
		}

		appCfg, err := approval.LoadConfig(settings)
		if err != nil {
			fmt.Fprintf(os.Stderr, "approval config: %v\n", err)
			os.Exit(1)
		}

		store, err := approval.OpenSQLiteStore(appCfg.Store)
		if err != nil {
			fmt.Fprintf(os.Stderr, "approval store: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = store.Close() }()

		svc := approval.NewService(store, appCfg)
		tg, err := approval.NewTelegramProviderFromSettings(svc, settings)
		if err != nil {
			fmt.Fprintf(os.Stderr, "telegram: %v\n", err)
			os.Exit(1)
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		fmt.Fprintln(os.Stderr, "listening for Telegram approval callbacks (Ctrl+C to stop)...")
		if err := tg.Poll(ctx); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "telegram poll: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	telegramCmd.AddCommand(telegramPollCmd)
	RootCmd.AddCommand(telegramCmd)
}
