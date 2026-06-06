package tools

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ba0f3/lunacli/internal/approval"
	"github.com/ba0f3/lunacli/internal/engine"
	"github.com/ba0f3/lunacli/internal/ssh"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerExecuteRemote(s *server.MCPServer, pool *ssh.Pool, eng *engine.Engine, gate *approval.Gate) {
	tool := mcp.NewTool("execute_remote",
		mcp.WithDescription(`Execute a shell command on a remote Linux host via SSH.

READ-ONLY BY DEFAULT: Commands that modify system state require out-of-band human
approval via Telegram (or configured provider). The tool blocks until the human
approves or denies, or the approval expires.

Optional approval_id: supply a UUID from a prior interrupted call to resume
waiting on the same pending approval (same host, command, timeout_sec).

Returns: stdout, stderr, exit_code, duration, and security classification.

BLOCKED means permanently forbidden. PERMISSION_REQUIRED means approval was denied,
expired, invalid, or the wait was cancelled.`),
		mcp.WithString("host",
			mcp.Required(),
			mcp.Description("Target host in format [user@]hostname[:port] (e.g. ubuntu@192.168.1.50). Uses current user and port 22 if omitted."),
		),
		mcp.WithString("command",
			mcp.Required(),
			mcp.Description("Shell command to execute on the remote host"),
		),
		mcp.WithNumber("timeout_sec",
			mcp.Description("Execution timeout in seconds (default: 30, max: 300)"),
		),
		mcp.WithString("approval_id",
			mcp.Description("UUID from a prior PERMISSION_REQUIRED response; must exactly match the same host, command, and timeout_sec"),
		),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		host, err := req.RequireString("host")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		command, err := req.RequireString("command")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		canonicalHost, err := pool.CanonicalTarget(host)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("resolve SSH target: %v", err)), nil
		}

		timeoutSec := req.GetFloat("timeout_sec", 30)
		if timeoutSec <= 0 || timeoutSec > 300 {
			timeoutSec = 30
		}
		timeout := time.Duration(timeoutSec) * time.Second

		approvalID := strings.TrimSpace(req.GetString("approval_id", ""))
		logCommand := approval.RedactSecrets(command)

		check := eng.ClassifyTargets(command, []string{host, canonicalHost}, nil)
		log.Printf("execute_remote host=%s class=%s approval_id=%q cmd=%q",
			canonicalHost, check.Class, approvalID, logCommand)

		gateRes := gate.CheckExecuteRemote(check, canonicalHost, command, timeoutSec, approvalID)
		switch gateRes.Kind {
		case approval.GateBlocked:
			log.Printf("BLOCKED host=%s cmd=%q reason=%s", host, logCommand, check.Reason)
			return mcp.NewToolResultText(fmt.Sprintf(
				"%s\n\nCommand: %q\n\nThis command is permanently forbidden and cannot be executed.",
				gateRes.BlockedText, command,
			)), nil
		case approval.GatePermissionRequired:
			if gateRes.ApprovalID != "" && approvalID == "" {
				log.Printf("waiting for approval %s host=%s cmd=%q", gateRes.ApprovalID, host, logCommand)
				waitCtx := ctx
				if deadline, ok := ctx.Deadline(); !ok || gateRes.ExpiresAt.Before(deadline) {
					var cancel context.CancelFunc
					waitCtx, cancel = context.WithDeadline(ctx, gateRes.ExpiresAt)
					defer cancel()
				}
				if _, waitErr := gate.WaitForDecision(waitCtx, gateRes.ApprovalID); waitErr != nil {
					log.Printf("approval wait ended host=%s id=%s err=%v", host, gateRes.ApprovalID, waitErr)
					return mcp.NewToolResultText(formatApprovalWaitError(waitErr, gateRes)), nil
				}
				gateRes = gate.CheckExecuteRemote(check, canonicalHost, command, timeoutSec, gateRes.ApprovalID)
				if gateRes.Kind != approval.GateExecute {
					log.Printf("PERMISSION_REQUIRED after wait host=%s cmd=%q", host, logCommand)
					return mcp.NewToolResultText(gateRes.PermissionText), nil
				}
				if check.Class == engine.Mutating {
					log.Printf("MUTATING APPROVED host=%s cmd=%q", host, logCommand)
				}
				break
			}
			log.Printf("PERMISSION_REQUIRED host=%s cmd=%q", host, logCommand)
			return mcp.NewToolResultText(gateRes.PermissionText), nil
		case approval.GateExecute:
			if check.Class == engine.Mutating {
				log.Printf("MUTATING APPROVED host=%s cmd=%q", host, logCommand)
			}
		default:
			return mcp.NewToolResultError("internal error: unknown gate result"), nil
		}

		result, err := pool.ExecuteBound(host, canonicalHost, command, timeout)
		if err != nil {
			if msg := ssh.AccessErrorMessage(err); msg != "" {
				return mcp.NewToolResultText(msg), nil
			}
			return mcp.NewToolResultError(fmt.Sprintf("SSH execution error: %v", err)), nil
		}

		log.Printf("execute_remote host=%s exit=%d duration=%s",
			host, result.ExitCode, result.Duration)

		return mcp.NewToolResultText(formatExecResult(host, command, check, result)), nil
	})
}

func formatExecResult(host, command string, check engine.Result, r ssh.ExecResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Host:     %s\n", host)
	fmt.Fprintf(&b, "Command:  %s\n", command)
	fmt.Fprintf(&b, "Class:    %s\n", check.Class)
	fmt.Fprintf(&b, "Exit:     %d\n", r.ExitCode)
	fmt.Fprintf(&b, "Duration: %s\n", r.Duration.Round(time.Millisecond))
	if check.Class == engine.Mutating {
		b.WriteString("Mutations: APPROVED\n")
	}

	b.WriteString("\n--- STDOUT ---\n")
	if strings.TrimSpace(r.Stdout) == "" {
		b.WriteString("(empty)\n")
	} else {
		b.WriteString(r.Stdout)
		if !strings.HasSuffix(r.Stdout, "\n") {
			b.WriteString("\n")
		}
	}

	if r.Stderr != "" {
		b.WriteString("\n--- STDERR ---\n")
		b.WriteString(r.Stderr)
		if !strings.HasSuffix(r.Stderr, "\n") {
			b.WriteString("\n")
		}
	}

	return b.String()
}

func formatApprovalWaitError(waitErr error, gateRes approval.GateResult) string {
	switch {
	case errors.Is(waitErr, approval.ErrDenied):
		return fmt.Sprintf("PERMISSION_REQUIRED: approval denied\n\napproval_id: %s", gateRes.ApprovalID)
	case errors.Is(waitErr, approval.ErrExpired):
		return fmt.Sprintf("PERMISSION_REQUIRED: approval expired\n\napproval_id: %s\nexpires_at: %s",
			gateRes.ApprovalID, gateRes.ExpiresAt.UTC().Format(time.RFC3339))
	case errors.Is(waitErr, context.DeadlineExceeded), errors.Is(waitErr, context.Canceled):
		return fmt.Sprintf("PERMISSION_REQUIRED: approval wait ended (%v)\n\napproval_id: %s\nexpires_at: %s\n\nApprove via Telegram, then retry with the same host, command, timeout_sec, and approval_id.",
			waitErr, gateRes.ApprovalID, gateRes.ExpiresAt.UTC().Format(time.RFC3339))
	default:
		return fmt.Sprintf("PERMISSION_REQUIRED: %v\n\n%s", waitErr, gateRes.PermissionText)
	}
}
