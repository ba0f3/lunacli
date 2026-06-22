package approval

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
)

const telegramDefaultAPIBase = "https://api.telegram.org"

// ErrTelegramCallbackUnauthorized means the Telegram user is not the configured approver.
var ErrTelegramCallbackUnauthorized = errors.New("telegram callback unauthorized")

// TelegramProvider sends approval prompts via Telegram Bot API sendMessage with an inline keyboard.
type TelegramProvider struct {
	svc                 *Service
	botToken            string
	approverUserID      string
	chatID              string
	apiBase             string
	httpClient          *http.Client
	sendMessagePath     string
	getUpdatesPath      string
	answerCallbackPath  string
	editMessageTextPath string
}

type telegramSendMessageBody struct {
	ChatID      string               `json:"chat_id"`
	Text        string               `json:"text"`
	ParseMode   string               `json:"parse_mode,omitempty"`
	ReplyMarkup *telegramReplyMarkup `json:"reply_markup,omitempty"`
}

type telegramReplyMarkup struct {
	InlineKeyboard [][]telegramInlineButton `json:"inline_keyboard"`
}

type telegramInlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type telegramAPIResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
}

type telegramSendMessageResponse struct {
	OK     bool `json:"ok"`
	Result struct {
		MessageID int64 `json:"message_id"`
		Chat      struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	} `json:"result"`
}

// TelegramProviderOptions configures TelegramProvider for tests or advanced setups.
type TelegramProviderOptions struct {
	BotToken       string
	ApproverUserID string
	ChatID         string // optional; defaults to ApproverUserID when empty (private chat with bot)
	APIBaseURL     string // optional; default https://api.telegram.org
	HTTPClient     *http.Client
	// SendMessagePathFmt is fmt format with one verb for bot token, e.g. "/bot%s/sendMessage".
	SendMessagePathFmt string
	// GetUpdatesPathFmt overrides getUpdates path for tests (default "/bot%s/getUpdates").
	GetUpdatesPathFmt string
	// AnswerCallbackPathFmt overrides answerCallbackQuery path (default "/bot%s/answerCallbackQuery").
	AnswerCallbackPathFmt string
	// EditMessageTextPathFmt overrides editMessageText path (default "/bot%s/editMessageText").
	EditMessageTextPathFmt string
}

// NewTelegramProvider constructs a Telegram provider. Prefer NewTelegramProviderFromEnv for production.
func NewTelegramProvider(svc *Service, opt TelegramProviderOptions) (*TelegramProvider, error) {
	if svc == nil {
		return nil, errors.New("telegram provider: nil service")
	}
	token := strings.TrimSpace(opt.BotToken)
	if token == "" {
		return nil, errors.New("telegram provider: empty bot token")
	}
	approver := strings.TrimSpace(opt.ApproverUserID)
	if approver == "" {
		return nil, errors.New("telegram provider: empty approver user id")
	}
	chat := strings.TrimSpace(opt.ChatID)
	if chat == "" {
		chat = approver
	}
	base := strings.TrimSuffix(strings.TrimSpace(opt.APIBaseURL), "/")
	if base == "" {
		base = telegramDefaultAPIBase
	}
	pathFmt := opt.SendMessagePathFmt
	if pathFmt == "" {
		pathFmt = "/bot%s/sendMessage"
	}
	sendPath := fmt.Sprintf(pathFmt, token)
	getUpdatesFmt := opt.GetUpdatesPathFmt
	if getUpdatesFmt == "" {
		getUpdatesFmt = "/bot%s/getUpdates"
	}
	answerFmt := opt.AnswerCallbackPathFmt
	if answerFmt == "" {
		answerFmt = "/bot%s/answerCallbackQuery"
	}
	editFmt := opt.EditMessageTextPathFmt
	if editFmt == "" {
		editFmt = "/bot%s/editMessageText"
	}
	client := opt.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	return &TelegramProvider{
		svc:                 svc,
		botToken:            token,
		approverUserID:      approver,
		chatID:              chat,
		apiBase:             base,
		httpClient:          client,
		sendMessagePath:     sendPath,
		getUpdatesPath:      fmt.Sprintf(getUpdatesFmt, token),
		answerCallbackPath:  fmt.Sprintf(answerFmt, token),
		editMessageTextPath: fmt.Sprintf(editFmt, token),
	}, nil
}

// Name implements Provider.
func (tg *TelegramProvider) Name() string { return "telegram" }

type sanitizedError struct {
	err error
	msg string
}

func (s *sanitizedError) Error() string        { return s.msg }
func (s *sanitizedError) Is(target error) bool { return errors.Is(s.err, target) }
func (s *sanitizedError) As(target any) bool {
	if _, ok := target.(**url.Error); ok {
		return false
	}
	if targetNetErr, ok := target.(*net.Error); ok {
		*targetNetErr = s
		return true
	}
	// SEC: Do not delegate to errors.As(s.err, target).
	// url.Error implements interfaces that could allow a caller to extract it and leak the token.
	return false
}

func (s *sanitizedError) Timeout() bool {
	var ne net.Error
	if errors.As(s.err, &ne) {
		return ne.Timeout()
	}
	return false
}

func (s *sanitizedError) Temporary() bool {
	var ne net.Error
	if errors.As(s.err, &ne) {
		return ne.Temporary()
	}
	return false
}

func (tg *TelegramProvider) sanitizeError(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	if tg.botToken != "" {
		s = strings.ReplaceAll(s, tg.botToken, "[REDACTED]")
		s = strings.ReplaceAll(s, url.QueryEscape(tg.botToken), "[REDACTED]")
		s = strings.ReplaceAll(s, url.PathEscape(tg.botToken), "[REDACTED]")
		// Also handle HTML escape which might be reflected by WAFs in error pages
		s = strings.ReplaceAll(s, html.EscapeString(tg.botToken), "[REDACTED]")
		s = strings.ReplaceAll(s, strings.ReplaceAll(tg.botToken, ":", "&#58;"), "[REDACTED]")
	}
	return &sanitizedError{err: err, msg: s}
}

// Notify implements Provider.
func (tg *TelegramProvider) Notify(pending PendingInfo, req ExecuteRemoteRequest) error {
	text := formatTelegramPendingMessage(pending, req)
	body := telegramSendMessageBody{
		ChatID:    tg.chatID,
		Text:      text,
		ParseMode: telegramParseModeHTML,
		ReplyMarkup: &telegramReplyMarkup{
			InlineKeyboard: [][]telegramInlineButton{
				{
					{Text: "✅ Approve", CallbackData: "approve:" + pending.ID},
					{Text: "❌ Deny", CallbackData: "deny:" + pending.ID},
				},
			},
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("telegram sendMessage: marshal body: %w", err)
	}
	urlStr := tg.apiBase + tg.sendMessagePath
	httpReq, err := http.NewRequest(http.MethodPost, urlStr, bytes.NewReader(payload))
	if err != nil {
		return tg.sanitizeError(fmt.Errorf("telegram sendMessage: build request: %w", err))
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := tg.httpClient.Do(httpReq)
	if err != nil {
		return tg.sanitizeError(fmt.Errorf("telegram sendMessage: %w", err))
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return tg.sanitizeError(fmt.Errorf("telegram sendMessage: read response: %w", err))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return tg.sanitizeError(fmt.Errorf("telegram sendMessage: HTTP %s: %s", resp.Status, strings.TrimSpace(string(respBody))))
	}

	var api telegramSendMessageResponse
	if err := json.Unmarshal(respBody, &api); err != nil {
		return tg.sanitizeError(fmt.Errorf("telegram sendMessage: decode response: %w", err))
	}
	if !api.OK {
		return tg.sanitizeError(fmt.Errorf("telegram sendMessage: api error: %s", strings.TrimSpace(string(respBody))))
	}
	if api.Result.MessageID != 0 {
		chatID := api.Result.Chat.ID
		if chatID == 0 {
			if parsed, err := strconv.ParseInt(tg.chatID, 10, 64); err == nil {
				chatID = parsed
			}
		}
		_ = tg.svc.SetTelegramMessage(pending.ID, chatID, api.Result.MessageID)
	}
	return nil
}

// HandleCallback applies an inline-keyboard callback after verifying the Telegram user id.
// data must be approve:<id> or deny:<id>.
func (tg *TelegramProvider) HandleCallback(userID string, data string) error {
	action, approvalID, ok := parseTelegramCallback(strings.TrimSpace(data))
	if !ok {
		return fmt.Errorf("telegram callback: invalid callback_data")
	}

	normalizedCaller := strings.TrimSpace(userID)
	normalizedApprover := strings.TrimSpace(tg.approverUserID)
	if normalizedCaller != normalizedApprover {
		if _, err := tg.svc.Get(approvalID); err == nil {
			detail := fmt.Sprintf(`{"telegram_user_id":%q,"expected":%q}`, normalizedCaller, normalizedApprover)
			_ = tg.svc.AppendAudit(AuditEvent{
				ApprovalID: approvalID,
				EventType:  "telegram_callback_unauthorized",
				Detail:     detail,
				CreatedAt:  time.Now().UTC(),
			})
		}
		return ErrTelegramCallbackUnauthorized
	}

	approverLabel := normalizedCaller
	switch action {
	case "approve":
		return tg.svc.Approve(approvalID, approverLabel, tg.Name())
	case "deny":
		return tg.svc.Deny(approvalID, approverLabel, tg.Name())
	default:
		return fmt.Errorf("telegram callback: unknown action %q", action)
	}
}

func parseTelegramCallback(data string) (action string, approvalID string, ok bool) {
	action, rest, found := strings.Cut(data, ":")
	if !found || strings.TrimSpace(action) == "" || strings.TrimSpace(rest) == "" {
		return "", "", false
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "approve":
		return "approve", strings.TrimSpace(rest), true
	case "deny":
		return "deny", strings.TrimSpace(rest), true
	default:
		return "", "", false
	}
}

// NewTelegramProviderFromSettings constructs TelegramProvider from config files and env.
func NewTelegramProviderFromSettings(svc *Service, cfg *config.Settings) (*TelegramProvider, error) {
	token, err := cfg.TelegramBotToken()
	if err != nil {
		return nil, err
	}
	approver := cfg.TelegramApproverUserID()
	if approver == "" {
		return nil, errors.New("telegram approver_user_id is required (config or LUNA_TELEGRAM_APPROVER_USER_ID)")
	}
	return NewTelegramProvider(svc, TelegramProviderOptions{
		BotToken:       token,
		ApproverUserID: approver,
		ChatID:         cfg.TelegramChatID(),
	})
}

// NewTelegramProviderFromEnv constructs TelegramProvider using JSON config and LUNA_TELEGRAM_* env.
func NewTelegramProviderFromEnv(svc *Service) (*TelegramProvider, error) {
	s, err := config.LoadSettings()
	if err != nil {
		return nil, err
	}
	return NewTelegramProviderFromSettings(svc, s)
}
