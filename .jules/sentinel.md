## 2026-05-31 - [Telegram Token Leak Prevention]
**Vulnerability:** Telegram bot tokens were leaking in HTTP error strings. When `http.Client.Do()` fails (e.g. network failure), it returns a `url.Error` which includes the requested URL. Because Telegram API URLs contain the token (e.g. `/bot<TOKEN>/...`), this token leaked into logs.
**Learning:** Go's `url.Error` includes the full URL in the error message string, which inadvertently exposes secrets embedded in the URL path.
**Prevention:** In Go, network errors must be manually string-sanitized (e.g. `strings.ReplaceAll(err.Error(), token, "[REDACTED]")`) and returned as flattened string errors (`errors.New`) to prevent structured loggers from unwrapping the error and logging the inner `url.Error` and its URL.
