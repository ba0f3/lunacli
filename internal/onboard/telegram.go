package onboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// ReadBotToken loads a trimmed bot token from a token file.
func ReadBotToken(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read bot token file %s: %w", path, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("bot token file %q is empty", path)
	}
	return token, nil
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

		reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(raw))
		if err != nil {
			cancel()
			return "", "", sanitizeTokenError(err, token)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			return "", "", sanitizeTokenError(err, token)
		}

		if resp.StatusCode != http.StatusOK {
			cancel()
			resp.Body.Close()
			return "", "", fmt.Errorf("telegram getUpdates returned status %d", resp.StatusCode)
		}

		data, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); err == nil {
			err = closeErr
		}
		cancel()
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
	return errors.As(s.err, target)
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

func sanitizeTokenError(err error, token string) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	if token != "" {
		s = strings.ReplaceAll(s, token, "[REDACTED]")
	}
	return &sanitizedError{err: err, msg: s}
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
