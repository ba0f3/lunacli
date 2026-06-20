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

## 2026-06-13 - [Telegram Token Leak Prevention - Block Interface Extraction in As]
**Vulnerability:** The custom `sanitizedError` wrapper implemented `As(target any) bool` by naively calling `errors.As(s.err, target)` as a fallback. This allowed callers doing `errors.As(err, &unwrapInterface)` (where `unwrapInterface` is `interface{ Unwrap() error }` or similar) to bypass sanitization. The `errors.As` logic checks if the inner error implements the interface, meaning `*url.Error` could be extracted if it matches the interface, subsequently leaking the Telegram bot token via `netErr.Error()`.
**Learning:** `errors.As` works across interfaces. Even if `Unwrap()` is not implemented, implementing `As` by delegating directly to the underlying error allows any interface that the underlying error implements to be extracted.
**Prevention:** In custom sanitized error wrappers, explicitly intercept `errors.As` calls for `**url.Error` returning `false`, intercept interfaces like `*net.Error` by assigning the wrapper to the target, and most importantly, DO NOT delegate to `errors.As(s.err, target)`. Instead, return `false` as a fallback to prevent the extraction of the underlying error through interfaces.

## 2026-06-19 - [Telegram Token Leak Prevention - HTTP Response Body]
**Vulnerability:** Telegram API errors when polling updates or sending messages could return HTTP response bodies containing HTML or error strings from WAFs/proxies that reflect the requested URL, thereby leaking the Telegram bot token via `io.ReadAll` or JSON parsing error messages.
**Learning:** Just sanitizing `http.Client.Do()` errors isn't enough; any error from processing the HTTP response (reading the body, parsing JSON, or returning non-2xx status codes) must also be sanitized because the error string could include the response body which might reflect the URL and its embedded token.
**Prevention:** Apply the custom `sanitizeTokenError` (or `tg.sanitizeError`) to ALL errors returned from the HTTP interaction lifecycle, including `io.ReadAll`, `json.Unmarshal`, and status code checks.

## 2026-06-20 - [Telegram Token Leak Prevention - WAF/Proxy Encoding]
**Vulnerability:** Telegram bot tokens were not fully redacted if a WAF/proxy reflected the requested URL using URL-encoding (e.g. `%3A` instead of `:`) or HTML-encoding (`&#58;`). A simple `strings.ReplaceAll(s, token, "[REDACTED]")` would miss these encoded variants, resulting in a token leak in error logs.
**Learning:** Reflected tokens in HTTP error pages may be transformed by WAFs or proxies through URL or HTML encoding. String replacement sanitization must account for these encoded forms.
**Prevention:** When sanitizing secrets from HTTP error bodies or URLs, always also redact the URL-escaped (`url.QueryEscape`, `url.PathEscape`) and HTML-escaped variants of the secret to ensure defense in depth against reflection attacks or logging leaks.