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
	Long: `List, inspect, approve, or deny pending execute_remote approval requests.

Approve and deny require your Unix uid to be listed in cli.approver_users
(config) or LUNA_CLI_APPROVER_USERS.`,
}

func runApprovals(args []string) {
	svc, cleanup, err := openApprovalService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()
	if err := approval.RunApprovalsCLI(args, svc); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func openApprovalService() (*approval.Service, func(), error) {
	settings, err := config.LoadSettings()
	if err != nil {
		return nil, nil, err
	}
	appCfg, err := approval.LoadConfig(settings)
	if err != nil {
		return nil, nil, err
	}
	store, err := approval.OpenSQLiteStore(appCfg.Store)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = store.Close() }
	return approval.NewService(store, appCfg), cleanup, nil
}

var approvalsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List pending approval requests",
	Run: func(cmd *cobra.Command, args []string) {
		runApprovals([]string{"list"})
	},
}

var approvalsShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show one approval request as JSON",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runApprovals(append([]string{"show"}, args...))
	},
}

var approvalsApproveCmd = &cobra.Command{
	Use:   "approve <id>",
	Short: "Approve a pending request (authorized uid required)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runApprovals(append([]string{"approve"}, args...))
	},
}

var approvalsDenyCmd = &cobra.Command{
	Use:   "deny <id>",
	Short: "Deny a pending request (authorized uid required)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runApprovals(append([]string{"deny"}, args...))
	},
}

func init() {
	approvalsCmd.AddCommand(approvalsListCmd, approvalsShowCmd, approvalsApproveCmd, approvalsDenyCmd)
	RootCmd.AddCommand(approvalsCmd)
}
