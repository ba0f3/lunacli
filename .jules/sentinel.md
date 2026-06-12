## 2026-05-31 - [Telegram Token Leak Prevention]
**Vulnerability:** Telegram bot tokens were leaking in HTTP error strings. When `http.Client.Do()` fails (e.g. network failure), it returns a `url.Error` which includes the requested URL. Because Telegram API URLs contain the token (e.g. `/bot<TOKEN>/...`), this token leaked into logs.
**Learning:** Go's `url.Error` includes the full URL in the error message string, which inadvertently exposes secrets embedded in the URL path.
**Prevention:** In Go, network errors must be manually string-sanitized (e.g. `strings.ReplaceAll(err.Error(), token, "[REDACTED]")`) and returned as flattened string errors (`errors.New`) to prevent structured loggers from unwrapping the error and logging the inner `url.Error` and its URL.

## 2026-06-09 - [Telegram Token Leak Prevention - Fixed Error Propagation]
**Vulnerability:** The previous security fix for url.Error token leak flattened errors using errors.New(s), breaking the error chain and causing errors.Is(err, context.Canceled) to fail.
**Learning:** Implementing a custom error wrapper that only overrides Error(), Is(), and As(), but crucially omitting Unwrap(), fixes the issue. If Unwrap() is implemented, loggers will traverse down the error chain and accidentally log the original unredacted error.
**Prevention:** When creating custom sanitized error wrappers for logging security, ensure Is() and As() are implemented, but NEVER implement Unwrap() if the wrapped error contains a secret.

## 2026-06-09 - [Telegram Token Leak Prevention - Fixed Error.As Leak]
**Vulnerability:** The custom `sanitizedError` wrapper implemented `As(target any) bool` by naively calling `errors.As(s.err, target)`. This allowed callers doing `errors.As(err, &netErr)` to bypass sanitization and extract the underlying `url.Error` into a `net.Error` interface, which subsequently leaked the Telegram bot token via `netErr.Error()`.
**Learning:** `errors.As` works across interfaces. Even if `Unwrap()` is not implemented, implementing `As` by delegating directly to the underlying error allows any interface (like `net.Error`) that the underlying error implements to be extracted.
**Prevention:** In custom sanitized error wrappers, explicitly intercept `errors.As` calls for `**url.Error` returning `false`, and intercept interfaces like `*net.Error` by implementing the interface (`Timeout()` and `Temporary()`) on the wrapper itself and assigning the wrapper to the target.
