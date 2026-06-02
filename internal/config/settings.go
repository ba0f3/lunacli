package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const (
	localConfigFile           = "luna.config.json"
	cwdConfigJSONRelPath      = ".config/luna.config.json"
	userConfigRelPath         = ".config/luna/config.json"
	homeLunaConfigJSONRelPath = ".config/luna/luna.config.json"
	dotEnvFile                = ".env"
)

// FileSettings is the JSON configuration schema (all fields optional).
type FileSettings struct {
	ConfigDir string           `json:"config_dir"`
	Approval  ApprovalSettings `json:"approval"`
	Telegram  TelegramSettings `json:"telegram"`
	Audit     AuditSettings    `json:"audit"`
}

type ApprovalSettings struct {
	TTL string `json:"ttl"`
}

type TelegramSettings struct {
	BotToken       string `json:"bot_token"`
	BotTokenFile   string `json:"bot_token_file"`
	ApproverUserID string `json:"approver_user_id"`
	ChatID         string `json:"chat_id"`
}

type AuditSettings struct {
	File string `json:"file"`
}

// Settings holds merged file configuration; use accessor methods for env overrides.
type Settings struct {
	file FileSettings
}

// LoadSettings reads configuration files then exposes values via accessors that
// apply environment overrides.
//
// Precedence (lowest to highest): JSON config files (~/.config/luna/config.json,
// ~/.config/luna/luna.config.json, then $CWD/.config/luna/config.json, then
// $CWD/.config/luna.config.json, then $CWD/luna.config.json), then $CWD/.env
// (does not override variables already set in the process environment).
func LoadSettings() (*Settings, error) {
	if err := loadDotEnv(); err != nil {
		return nil, err
	}

	var merged FileSettings

	for _, path := range settingsFilePaths() {
		fs, err := readSettingsFile(path)
		if err != nil {
			return nil, err
		}
		if fs != nil {
			mergeFileSettings(&merged, fs)
		}
	}

	return &Settings{file: merged}, nil
}

func loadDotEnv() error {
	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}
	path := filepath.Join(cwd, dotEnvFile)
	if err := godotenv.Load(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("load %s: %w", path, err)
	}
	return nil
}

func settingsFilePaths() []string {
	var paths []string
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, userConfigRelPath),
			filepath.Join(home, homeLunaConfigJSONRelPath),
		)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return paths
	}
	paths = append(paths,
		filepath.Join(cwd, userConfigRelPath),
		filepath.Join(cwd, cwdConfigJSONRelPath),
		filepath.Join(cwd, localConfigFile),
	)
	return paths
}

func readSettingsFile(path string) (*FileSettings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var fs FileSettings
	if err := json.Unmarshal(data, &fs); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &fs, nil
}

func mergeFileSettings(dst, src *FileSettings) {
	if src.ConfigDir != "" {
		dst.ConfigDir = src.ConfigDir
	}
	if src.Approval.TTL != "" {
		dst.Approval.TTL = src.Approval.TTL
	}
	if src.Telegram.BotToken != "" {
		dst.Telegram.BotToken = src.Telegram.BotToken
	}
	if src.Telegram.BotTokenFile != "" {
		dst.Telegram.BotTokenFile = src.Telegram.BotTokenFile
	}
	if src.Telegram.ApproverUserID != "" {
		dst.Telegram.ApproverUserID = src.Telegram.ApproverUserID
	}
	if src.Telegram.ChatID != "" {
		dst.Telegram.ChatID = src.Telegram.ChatID
	}
	if src.Audit.File != "" {
		dst.Audit.File = src.Audit.File
	}
}

func envFirst(envKey, fileVal string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	return strings.TrimSpace(fileVal)
}

// expandPath expands a leading ~ to the user home directory (~/.foo -> /home/user/.foo).
func expandPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	if len(path) > 1 && (path[1] == '/' || path[1] == '\\') {
		return filepath.Join(home, path[2:])
	}
	return path
}

// ConfigDir resolves the directory containing policy.yml and hosts.yml.
func (s *Settings) ConfigDir() string {
	if v := envFirst("LUNA_CONFIG_DIR", s.file.ConfigDir); v != "" {
		return resolveConfigDir(v)
	}
	return discoverConfigDir()
}

func hasPolicyFile(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "policy.yml"))
	return err == nil
}

func configDirBases() []string {
	var bases []string
	if cwd, err := os.Getwd(); err == nil {
		bases = append(bases, cwd)
	}
	if home, err := os.UserHomeDir(); err == nil {
		bases = append(bases, filepath.Join(home, ".config", "luna"))
	}
	return bases
}

func resolveConfigDir(dir string) string {
	dir = expandPath(dir)
	if hasPolicyFile(dir) {
		return dir
	}
	relPaths := []string{dir}
	if filepath.ToSlash(dir) == ".config/luna.d" {
		relPaths = append(relPaths, "luna.d")
	}
	for _, rel := range relPaths {
		if filepath.IsAbs(rel) && hasPolicyFile(rel) {
			return rel
		}
		for _, base := range configDirBases() {
			candidate := filepath.Join(base, rel)
			if hasPolicyFile(candidate) {
				abs, err := filepath.Abs(candidate)
				if err == nil {
					return abs
				}
				return candidate
			}
		}
	}
	return dir
}

func discoverConfigDir() string {
	candidates := []string{"./luna.d", "./.config/luna.d"}
	if home, err := os.UserHomeDir(); err == nil {
		lunaHome := filepath.Join(home, ".config", "luna")
		candidates = append(candidates,
			filepath.Join(lunaHome, "luna.d"),
			filepath.Join(lunaHome, ".config", "luna.d"),
			lunaHome,
		)
	}
	candidates = append(candidates, "/etc/luna")
	for _, dir := range candidates {
		if hasPolicyFile(dir) {
			return dir
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "luna")
	}
	return "/etc/luna"
}

// ApprovalTTL returns pending approval lifetime (default 5m).
func (s *Settings) ApprovalTTL() (time.Duration, error) {
	ttlStr := envFirst("LUNA_APPROVAL_TTL", s.file.Approval.TTL)
	if ttlStr == "" {
		return 5 * time.Minute, nil
	}
	d, err := time.ParseDuration(ttlStr)
	if err != nil {
		return 0, fmt.Errorf("invalid approval ttl %q: %w", ttlStr, err)
	}
	return d, nil
}

// AuditFile returns the audit log path if configured.
func (s *Settings) AuditFile() string {
	return expandPath(envFirst("LUNA_AUDIT_FILE", s.file.Audit.File))
}

// TelegramBotToken resolves bot token from env, inline json, or token file.
func (s *Settings) TelegramBotToken() (string, error) {
	if v := strings.TrimSpace(os.Getenv("LUNA_TELEGRAM_BOT_TOKEN")); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(s.file.Telegram.BotToken); v != "" {
		return v, nil
	}
	path := expandPath(envFirst("LUNA_TELEGRAM_BOT_TOKEN_FILE", s.file.Telegram.BotTokenFile))
	if path == "" {
		return "", errors.New("set telegram bot_token, bot_token_file in config, or LUNA_TELEGRAM_BOT_TOKEN / LUNA_TELEGRAM_BOT_TOKEN_FILE")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read telegram bot token file %s: %w", path, err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", fmt.Errorf("telegram bot token file %q is empty", path)
	}
	return tok, nil
}

func (s *Settings) TelegramApproverUserID() string {
	return envFirst("LUNA_TELEGRAM_APPROVER_USER_ID", s.file.Telegram.ApproverUserID)
}

func (s *Settings) TelegramChatID() string {
	return envFirst("LUNA_TELEGRAM_CHAT_ID", s.file.Telegram.ChatID)
}
