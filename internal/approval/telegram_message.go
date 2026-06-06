package approval

import (
	"errors"
	"fmt"
	"strings"
)

const (
	telegramParseModeHTML   = "HTML"
	telegramMaxCommandRunes = 280
)

func escapeTelegramHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func telegramShortID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func truncateTelegramCommand(cmd string) string {
	r := []rune(cmd)
	if len(r) <= telegramMaxCommandRunes {
		return cmd
	}
	return string(r[:telegramMaxCommandRunes-1]) + "…"
}

func telegramStatusEmoji(statusLabel string) string {
	switch strings.ToUpper(strings.TrimSpace(statusLabel)) {
	case "PENDING":
		return "⏳"
	case "APPROVED":
		return "✅"
	case "DENIED":
		return "❌"
	case "EXPIRED":
		return "⌛"
	case "CONSUMED":
		return "♻️"
	case "UNAUTHORIZED":
		return "🚫"
	case "NOT FOUND":
		return "❓"
	case "INVALID", "FAILED":
		return "⚠️"
	default:
		return "•"
	}
}

func formatTelegramPendingMessage(pending PendingInfo, req ExecuteRemoteRequest) string {
	if req.Tool == trustHostToolName {
		return formatTelegramTrustHostMessage(pending, req)
	}
	host := escapeTelegramHTML(req.Host)
	cmd := escapeTelegramHTML(truncateTelegramCommand(req.Command))
	shortID := escapeTelegramHTML(telegramShortID(pending.ID))
	expires := escapeTelegramHTML(pending.ExpiresAt.UTC().Format("15:04Z"))

	return fmt.Sprintf(
		"<b>🌙 Luna</b>  %s <b>PENDING</b>\n\n<code>%s</code>\n<pre>%s</pre>\n\n<code>%s</code> · ⌛ %s",
		telegramStatusEmoji("PENDING"),
		host,
		cmd,
		shortID,
		expires,
	)
}

func formatTelegramTrustHostMessage(pending PendingInfo, req ExecuteRemoteRequest) string {
	host := escapeTelegramHTML(req.Host)
	detail := escapeTelegramHTML(truncateTelegramCommand(req.Command))
	shortID := escapeTelegramHTML(telegramShortID(pending.ID))
	expires := escapeTelegramHTML(pending.ExpiresAt.UTC().Format("15:04Z"))

	return fmt.Sprintf(
		"<b>🌙 Luna</b>  %s <b>TRUST HOST</b>\n\n<code>%s</code>\n<pre>%s</pre>\n\n<code>%s</code> · ⌛ %s",
		telegramStatusEmoji("PENDING"),
		host,
		detail,
		shortID,
		expires,
	)
}

func formatTelegramResolvedMessage(rec Record, statusLabel, detail string) string {
	emoji := telegramStatusEmoji(statusLabel)
	label := escapeTelegramHTML(strings.ToUpper(strings.TrimSpace(statusLabel)))
	host := escapeTelegramHTML(rec.Host)
	cmd := escapeTelegramHTML(truncateTelegramCommand(rec.RedactedCommand))

	var b strings.Builder
	fmt.Fprintf(&b, "<b>🌙 Luna</b>  %s <b>%s</b>\n\n<code>%s</code>\n<pre>%s</pre>", emoji, label, host, cmd)
	if detail != "" {
		b.WriteString("\n\n<i>")
		b.WriteString(escapeTelegramHTML(detail))
		b.WriteString("</i>")
	}
	return b.String()
}

func telegramResolvedDetailForProvider(rec Record, actor, provider string, err error) string {
	if err != nil {
		if errors.Is(err, ErrTelegramCallbackUnauthorized) {
			return fmt.Sprintf("rejected %s", actor)
		}
		return err.Error()
	}
	who := strings.TrimSpace(rec.Approver)
	if who == "" {
		who = strings.TrimSpace(actor)
	}
	if provider == "" {
		return who
	}
	return fmt.Sprintf("via %s · %s", provider, who)
}
