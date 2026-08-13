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
## 2026-06-25 - [Telegram Token Leak Prevention - HTML Encoding completeness]
**Vulnerability:** Telegram bot tokens were not fully redacted if a WAF/proxy reflected the requested URL using HTML-encoding. A simple manual replacement of `":"` to `"&#58;"` was used, missing the complete standard Go `html.EscapeString()` implementation. Any special characters (`&`, `<`, `>`, `"`, `'`) within the token or properly HTML-escaped by a proxy were not redacted, resulting in a token leak in error logs.
**Learning:** Reflected tokens in HTTP error pages transformed by WAFs or proxies through HTML encoding require the use of standard library encoding methods like `html.EscapeString()` to ensure comprehensive redaction.
**Prevention:** When sanitizing secrets from HTTP error bodies or URLs, use standard encoding library functions (e.g., `html.EscapeString()`) to handle all potential HTML-escaped variants of the secret, replacing them comprehensively to ensure defense in depth against reflection attacks or logging leaks.

## 2026-06-29 - [Missing API Timeout]
**Vulnerability:** The Telegram provider `Notify` method invoked `http.NewRequest` and `client.Do()` without passing an explicit timeout context, meaning the application could hang indefinitely if the API or proxy became unresponsive.
**Learning:** `http.NewRequest` defaults to a context that never cancels. Combined with an unconfigured default client (which has no timeout), external calls can block forever leading to Denial of Service via resource exhaustion.
**Prevention:** Always use `http.NewRequestWithContext` combined with `context.WithTimeout` when making external API calls to guarantee bounded execution time.

## 2026-07-15 - [Unbounded Stream Reading]
**Vulnerability:** HTTP response bodies and uncompressed tarball contents were being read entirely into memory using `io.ReadAll(reader)`. This exposes the application to Denial of Service (DoS) attacks via memory exhaustion (OOM), as malicious endpoints or corrupted tarballs could return extremely large payloads.
**Learning:** `io.ReadAll` reads until EOF without any built-in size limit, allocating memory dynamically to fit the entire stream.
**Prevention:** To prevent memory exhaustion, always bound untrusted input streams by wrapping the reader in an `io.LimitReader(reader, maxSize)` before calling `io.ReadAll`, thereby setting a strict upper bound on the number of bytes read into memory.

## 2026-07-20 - [Unbounded Stream Reading during JSON Decode]
**Vulnerability:** Similar to `io.ReadAll`, passing an HTTP response body directly to `json.NewDecoder(resp.Body).Decode(&v)` can lead to Denial of Service (DoS) attacks via memory exhaustion (OOM). A malicious or misconfigured upstream API could return an extremely large payload, which `json.NewDecoder` will attempt to parse entirely into memory.
**Learning:** `json.NewDecoder` does not inherently bound the size of the stream it reads, making it vulnerable to large payload attacks just like `io.ReadAll`.
**Prevention:** Always bound untrusted input streams before passing them to `json.NewDecoder` by wrapping the reader in an `io.LimitReader(reader, maxSize)`, thereby setting a strict upper bound on the number of bytes read and decoded into memory.

## 2026-07-31 - [http.DefaultClient Timeout Vulnerability]
**Vulnerability:** The codebase was using `http.DefaultClient` in the Telegram integration, which lacks a configured timeout. This could lead to goroutine leaks and eventual resource exhaustion (Denial of Service) if the Telegram API or proxy hangs indefinitely.
**Learning:** In Go, `http.DefaultClient` does not have a timeout. While `context.WithTimeout` on requests helps, relying on the default client itself is risky and can lead to resource exhaustion if contexts aren't carefully managed.
**Prevention:** Avoid `http.DefaultClient` in production code. Always instantiate a custom `http.Client` with an explicit `Timeout` (e.g., `&http.Client{Timeout: 30 * time.Second}`).
