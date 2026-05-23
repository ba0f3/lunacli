package onboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func SaveBotToken(path, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("empty bot token")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(token+"\n"), 0600)
}

// DiscoverApprover polls getUpdates for a user message (e.g. /start).
// apiBaseFmt is like "https://api.telegram.org/bot%s/" (trailing slash optional).
func DiscoverApprover(ctx context.Context, token string, client *http.Client, apiBaseFmt string) (approverID, chatID string, err error) {
	if client == nil {
		client = http.DefaultClient
	}
	if apiBaseFmt == "" {
		apiBaseFmt = "https://api.telegram.org/bot%s/"
	}
	base := fmt.Sprintf(apiBaseFmt, token)
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	url := base + "getUpdates"

	deadline := time.Now().Add(2 * time.Minute)
	var lastUpdateID int64
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		body := map[string]any{
			"timeout":         25,
			"offset":          lastUpdateID + 1,
			"allowed_updates": []string{"message"},
		}
		raw, err := json.Marshal(body)
		if err != nil {
			return "", "", err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
		if err != nil {
			return "", "", err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return "", "", err
		}
		data, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return "", "", err
		}
		var parsed telegramUpdatesResponse
		if err := json.Unmarshal(data, &parsed); err != nil {
			return "", "", err
		}
		if !parsed.OK {
			return "", "", fmt.Errorf("telegram getUpdates: %s", parsed.Description)
		}
		var lastMsg *telegramMessage
		for _, u := range parsed.Result {
			if u.UpdateID > lastUpdateID {
				lastUpdateID = u.UpdateID
			}
			if u.Message != nil && u.Message.From != nil {
				lastMsg = u.Message
			}
		}
		if lastMsg != nil {
			return strconv.FormatInt(lastMsg.From.ID, 10),
				strconv.FormatInt(lastMsg.Chat.ID, 10), nil
		}
	}
	return "", "", fmt.Errorf("no Telegram message received; send /start to your bot and retry")
}

type telegramUpdatesResponse struct {
	OK          bool             `json:"ok"`
	Description string           `json:"description"`
	Result      []telegramUpdate `json:"result"`
}

type telegramUpdate struct {
	UpdateID int64            `json:"update_id"`
	Message  *telegramMessage `json:"message,omitempty"`
}

type telegramMessage struct {
	From *telegramUser `json:"from"`
	Chat telegramChat  `json:"chat"`
	Text string        `json:"text"`
}

type telegramUser struct {
	ID int64 `json:"id"`
}

type telegramChat struct {
	ID int64 `json:"id"`
}
