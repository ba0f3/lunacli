package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
)

// RunApprovalsCLI runs subcommands list, show, approve, or deny against svc.
func RunApprovalsCLI(args []string, svc *Service) error {
	settings, err := config.LoadSettings()
	if err != nil {
		return err
	}
	allowed := settings.CLIApproverUsers()

	if len(args) < 1 {
		return fmt.Errorf(`usage: <binary> approvals <list|show|approve|deny> [...]`)
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "list":
		return approvalsList(svc)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: approvals show <id>")
		}
		return approvalsShow(svc, strings.TrimSpace(args[1]))
	case "approve":
		if len(args) < 2 {
			return fmt.Errorf("usage: approvals approve <id>")
		}
		return approvalsApprove(svc, strings.TrimSpace(args[1]), allowed)
	case "deny":
		if len(args) < 2 {
			return fmt.Errorf("usage: approvals deny <id>")
		}
		return approvalsDeny(svc, strings.TrimSpace(args[1]), allowed)
	default:
		return fmt.Errorf("unknown approvals subcommand %q", args[0])
	}
}

func approvalsList(svc *Service) error {
	recs, err := svc.ListPending()
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		fmt.Fprintln(os.Stdout, "no pending approvals")
		return nil
	}
	for _, r := range recs {
		fmt.Fprintf(os.Stdout, "%s\t%s\t%s\t%s\n",
			r.ID, r.Host, r.RedactedCommand, r.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

func approvalsShow(svc *Service, id string) error {
	r, err := svc.Get(id)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func approvalsApprove(svc *Service, id, allowedCSV string) error {
	uid := fmt.Sprint(os.Getuid())
	if err := AuthorizeCLIApprover(uid, allowedCSV); err != nil {
		if _, gerr := svc.Get(id); gerr == nil {
			detail := fmt.Sprintf(`{"uid":%q,"error":%q}`, uid, err.Error())
			_ = svc.AppendAudit(AuditEvent{
				ApprovalID: id,
				EventType:  "cli_approve_unauthorized",
				Detail:     detail,
			})
		}
		return err
	}

	if err := svc.Approve(id, uid, "cli"); err != nil {
		return err
	}
	return nil
}

func approvalsDeny(svc *Service, id, allowedCSV string) error {
	uid := fmt.Sprint(os.Getuid())
	if err := AuthorizeCLIApprover(uid, allowedCSV); err != nil {
		if _, gerr := svc.Get(id); gerr == nil {
			detail := fmt.Sprintf(`{"uid":%q,"error":%q}`, uid, err.Error())
			_ = svc.AppendAudit(AuditEvent{
				ApprovalID: id,
				EventType:  "cli_deny_unauthorized",
				Detail:     detail,
			})
		}
		return err
	}
	return svc.Deny(id, uid, "cli")
}
