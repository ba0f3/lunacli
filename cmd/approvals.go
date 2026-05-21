package cmd

import (
	"fmt"
	"os"

	"github.com/ba0f3/lunacli/internal/approval"
	"github.com/ba0f3/lunacli/internal/config"
	"github.com/spf13/cobra"
)

var approvalsCmd = &cobra.Command{
	Use:   "approvals",
	Short: "Manage pending out-of-band approval requests",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		settings, err := config.LoadSettings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		appCfg, err := approval.LoadConfig(settings)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		store, err := approval.OpenSQLiteStore(appCfg.Store)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = store.Close() }()
		svc := approval.NewService(store, appCfg)
		if err := approval.RunApprovalsCLI(args, svc); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(approvalsCmd)
}
