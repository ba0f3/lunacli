package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const telegramLongPollSec = 30

type telegramGetUpdatesRequest struct {
	Offset         int64    `json:"offset,omitempty"`
	Timeout        int      `json:"timeout"`
	AllowedUpdates []string `json:"allowed_updates"`
}

type telegramUpdatesResponse struct {
	OK          bool             `json:"ok"`
	Description string           `json:"description"`
	Result      []telegramUpdate `json:"result"`
}

type telegramUpdate struct {
	UpdateID      int64                  `json:"update_id"`
	CallbackQuery *telegramCallbackQuery `json:"callback_query,omitempty"`
}

type telegramCallbackQuery struct {
	ID      string                   `json:"id"`
	From    telegramUser             `json:"from"`
	Message *telegramCallbackMessage `json:"message,omitempty"`
	Data    string                   `json:"data"`
}

type telegramUser struct {
	ID int64 `json:"id"`
}

type telegramCallbackMessage struct {
	MessageID int64        `json:"message_id"`
	Chat      telegramChat `json:"chat"`
}

type telegramChat struct {
	ID int64 `json:"id"`
}

type telegramEditMessageRequest struct {
	ChatID      int64                `json:"chat_id"`
	MessageID   int64                `json:"message_id"`
	Text        string               `json:"text"`
	ParseMode   string               `json:"parse_mode,omitempty"`
	ReplyMarkup *telegramReplyMarkup `json:"reply_markup"`
}

type telegramAnswerCallbackRequest struct {
	CallbackQueryID string `json:"callback_query_id"`
	Text            string `json:"text,omitempty"`
	ShowAlert       bool   `json:"show_alert,omitempty"`
}

// Poll runs long-polling getUpdates until ctx is cancelled, handling inline Approve/Deny callbacks.
func (tg *TelegramProvider) Poll(ctx context.Context) error {
	var offset int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		updates, err := tg.fetchUpdates(ctx, offset)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return err
		}

		for _, u := range updates {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			if u.CallbackQuery != nil {
				tg.handleCallbackQuery(ctx, u.CallbackQuery)
			}
		}
	}
}

func (tg *TelegramProvider) fetchUpdates(ctx context.Context, offset int64) ([]telegramUpdate, error) {
	body := telegramGetUpdatesRequest{
		Offset:         offset,
		Timeout:        telegramLongPollSec,
		AllowedUpdates: []string{"callback_query"},
	}
	var resp telegramUpdatesResponse
	if err := tg.postTelegram(ctx, tg.getUpdatesPath, body, &resp, telegramLongPollSec+10); err != nil {
		return nil, err
	}
	if !resp.OK {
		desc := strings.TrimSpace(resp.Description)
		if desc == "" {
			desc = "getUpdates returned ok=false"
		}
		return nil, fmt.Errorf("telegram getUpdates: %s", desc)
	}
	return resp.Result, nil
}

func (tg *TelegramProvider) handleCallbackQuery(ctx context.Context, cq *telegramCallbackQuery) {
	userID := strconv.FormatInt(cq.From.ID, 10)
	_, approvalID, hasID := parseTelegramCallback(strings.TrimSpace(cq.Data))

	err := tg.HandleCallback(userID, cq.Data)
	statusLabel, toast, alert := telegramCallbackAnswer(err, cq.Data)

	_ = tg.answerCallbackQuery(ctx, cq.ID, toast, alert)

	if cq.Message == nil {
		return
	}

	var rec Record
	if hasID {
		if updated, getErr := tg.svc.Get(approvalID); getErr == nil {
			rec = updated
		}
	}
	if rec.ID == "" {
		rec = Record{
			ID:              approvalID,
			RedactedCommand: "(unknown)",
		}
	}

	if hasID && cq.Message != nil {
		_ = tg.svc.SetTelegramMessage(approvalID, cq.Message.Chat.ID, cq.Message.MessageID)
	}

	editText := formatTelegramResolvedMessage(rec, statusLabel, telegramResolvedDetailForProvider(rec, userID, tg.Name(), err))
	_ = tg.editApprovalMessage(ctx, cq.Message.Chat.ID, cq.Message.MessageID, editText)
}

func telegramCallbackAnswer(err error, data string) (statusLabel, toast string, showAlert bool) {
	if err == nil {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(data)), "approve:") {
			return "APPROVED", "Approved", false
		}
		return "DENIED", "Denied", false
	}
	switch {
	case errors.Is(err, ErrTelegramCallbackUnauthorized):
		return "UNAUTHORIZED", "Not authorized", true
	case errors.Is(err, ErrDenied):
		return "DENIED", "Already denied", true
	case errors.Is(err, ErrExpired):
		return "EXPIRED", "Approval expired", true
	case errors.Is(err, ErrConsumed):
		return "CONSUMED", "Already used", true
	case errors.Is(err, ErrNotFound):
		return "NOT FOUND", "Unknown approval", true
	case errors.Is(err, ErrMismatch):
		return "INVALID", "Invalid state", true
	default:
		return "FAILED", err.Error(), true
	}
}

func (tg *TelegramProvider) editApprovalMessage(ctx context.Context, chatID, messageID int64, text string) error {
	body := telegramEditMessageRequest{
		ChatID:    chatID,
		MessageID: messageID,
		Text:      text,
		ParseMode: telegramParseModeHTML,
		ReplyMarkup: &telegramReplyMarkup{
			InlineKeyboard: [][]telegramInlineButton{},
		},
	}
	var resp telegramAPIResponse
	if err := tg.postTelegram(ctx, tg.editMessageTextPath, body, &resp, 15); err != nil {
		return err
	}
	if !resp.OK {
		desc := strings.TrimSpace(resp.Description)
		if desc == "" {
			desc = "editMessageText returned ok=false"
		}
		return fmt.Errorf("telegram editMessageText: %s", desc)
	}
	return nil
}

func (tg *TelegramProvider) answerCallbackQuery(ctx context.Context, callbackQueryID, text string, showAlert bool) error {
	body := telegramAnswerCallbackRequest{
		CallbackQueryID: callbackQueryID,
		Text:            text,
		ShowAlert:       showAlert,
	}
	var resp telegramAPIResponse
	if err := tg.postTelegram(ctx, tg.answerCallbackPath, body, &resp, 15); err != nil {
		return err
	}
	if !resp.OK {
		desc := strings.TrimSpace(resp.Description)
		if desc == "" {
			desc = "answerCallbackQuery returned ok=false"
		}
		return fmt.Errorf("telegram answerCallbackQuery: %s", desc)
	}
	return nil
}

func (tg *TelegramProvider) postTelegram(ctx context.Context, path string, body any, into any, timeoutSec int) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("telegram API: marshal: %w", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	urlStr := tg.apiBase + path
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, urlStr, bytes.NewReader(payload))
	if err != nil {
		return tg.sanitizeError(fmt.Errorf("telegram API: build request: %w", err))
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := tg.httpClient.Do(httpReq)
	if err != nil {
		return tg.sanitizeError(fmt.Errorf("telegram API: %w", err))
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return tg.sanitizeError(fmt.Errorf("telegram API: read response: %w", err))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return tg.sanitizeError(fmt.Errorf("telegram API: HTTP %s: %s", resp.Status, strings.TrimSpace(string(respBody))))
	}
	if into != nil {
		if err := json.Unmarshal(respBody, into); err != nil {
			return tg.sanitizeError(fmt.Errorf("telegram API: decode response: %w", err))
		}
	}
	return nil
}
