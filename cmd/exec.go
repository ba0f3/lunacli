package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ba0f3/lunacli/internal/approval"
	"github.com/ba0f3/lunacli/internal/config"
	"github.com/ba0f3/lunacli/internal/engine"
	"github.com/ba0f3/lunacli/internal/policy"
	"github.com/ba0f3/lunacli/internal/ssh"
	"github.com/spf13/cobra"
)

var (
	execApprovalID string
	execTimeoutSec float64
	execNoWait     bool
)

var execCmd = &cobra.Command{
	Use:   "exec [host] [command]",
	Short: "Execute a remote command with policy check and out-of-band approval",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]
		command := args[1]

		settings, err := config.LoadSettings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "config: %v\n", err)
			os.Exit(1)
		}

		pol, err := policy.LoadPolicy(settings.ConfigDir())
		if err != nil {
			fmt.Fprintf(os.Stderr, "policy required: %v\n", err)
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
		providers, err := approval.RemoteProvidersFromSettings(settings, svc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "approval providers: %v\n", err)
			os.Exit(1)
		}
		gate := approval.NewGate(appCfg, svc, providers)

		timeoutSec := execTimeoutSec
		if timeoutSec <= 0 || timeoutSec > 300 {
			timeoutSec = 30
		}
		timeout := time.Duration(timeoutSec) * time.Second

		eng := engine.NewEngine(pol)
		check := eng.Classify(command, host, nil)
		approvalID := strings.TrimSpace(execApprovalID)

		for {
			gateRes := gate.CheckExecuteRemote(check, host, command, timeoutSec, approvalID)

			switch gateRes.Kind {
			case approval.GateBlocked:
				fmt.Fprintf(os.Stderr, "%s\n", gateRes.BlockedText)
				os.Exit(1)
			case approval.GatePermissionRequired:
				if execNoWait {
					fmt.Fprintf(os.Stderr, "%s\n", gateRes.PermissionText)
					if gateRes.NotifyErr != nil {
						fmt.Fprintf(os.Stderr, "warning: approval notification failed: %v\n", gateRes.NotifyErr)
					}
					os.Exit(2)
				}
				if gateRes.ApprovalID == "" {
					fmt.Fprintln(os.Stderr, gateRes.PermissionText)
					os.Exit(2)
				}
				fmt.Fprintf(os.Stderr,
					"Approval required: %s\nWaiting for approval %s (expires %s).\nApprove via Telegram or: luna approvals approve %s\n",
					check.Reason,
					gateRes.ApprovalID,
					gateRes.ExpiresAt.UTC().Format(time.RFC3339),
					gateRes.ApprovalID,
				)
				if gateRes.NotifyErr != nil {
					fmt.Fprintf(os.Stderr, "warning: approval notification failed: %v\n", gateRes.NotifyErr)
				}
				waitCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
				if tg := providers.Telegram(); tg != nil {
					pollCtx, pollCancel := context.WithCancel(waitCtx)
					go func() {
						if err := tg.Poll(pollCtx); err != nil && !errors.Is(err, context.Canceled) {
							fmt.Fprintf(os.Stderr, "warning: telegram poll stopped: %v\n", err)
						}
					}()
					defer pollCancel()
				}
				_, waitErr := svc.WaitForDecision(waitCtx, gateRes.ApprovalID)
				stop()
				if waitErr != nil {
					if errors.Is(waitErr, approval.ErrDenied) {
						fmt.Fprintf(os.Stderr, "approval denied: %s\n", gateRes.ApprovalID)
						os.Exit(1)
					}
					if errors.Is(waitErr, approval.ErrExpired) {
						fmt.Fprintf(os.Stderr, "approval expired: %s\n", gateRes.ApprovalID)
						os.Exit(1)
					}
					if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
						fmt.Fprintf(os.Stderr, "approval wait cancelled\n")
						os.Exit(130)
					}
					fmt.Fprintf(os.Stderr, "approval wait failed: %v\n", waitErr)
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "approved; executing...\n")
				approvalID = gateRes.ApprovalID
				continue
			case approval.GateExecute:
				pool := ssh.NewPool()
				execRes, err := pool.Execute(host, command, timeout)
				if err != nil {
					fmt.Fprintf(os.Stderr, "SSH error: %v\n", err)
					os.Exit(1)
				}

				fmt.Print(execRes.Stdout)
				if execRes.Stderr != "" {
					fmt.Fprintln(os.Stderr, execRes.Stderr)
				}
				os.Exit(execRes.ExitCode)
			default:
				fmt.Fprintln(os.Stderr, "internal error: unknown gate result")
				os.Exit(1)
			}
		}
	},
}

func init() {
	execCmd.Flags().StringVar(&execApprovalID, "approval-id", "", "skip wait and use an existing approval UUID (non-interactive retry)")
	execCmd.Flags().Float64Var(&execTimeoutSec, "timeout-sec", 30, "Execution timeout in seconds (max 300)")
	execCmd.Flags().BoolVar(&execNoWait, "no-wait", false, "exit with PERMISSION_REQUIRED instead of waiting for approval")
	RootCmd.AddCommand(execCmd)
}
