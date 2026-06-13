package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
)

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
	// Let's implement As by doing type-assertion loops to prevent URL leaks through interfaces.
	// But it's actually much simpler: we only care about NOT leaking the url.Error when target is an interface.
	// If we just check what target points to. BUT `target` is of type `any` (so it's a pointer to the interface).
	// We can't really inspect it properly.

	// Since we ONLY care about standard errors, let's just NOT delegate to `errors.As(s.err, target)`.
	// Why do we even delegate? If we don't, then `errors.Is` still works because we implemented `Is`.
	// But what if the user wants `os.PathError` inside `s.err`? `net/http` rarely returns that directly except wrapped in url.Error.

	// In the real code, `sanitizeTokenError` is only used for:
	// - req, err := http.NewRequestWithContext(...)
	// - resp, err := client.Do(req)
	// Both of these mostly return *url.Error.
	// If we just return `false` here, it breaks `errors.As` for anything other than `*net.Error` (which we handle) and `**url.Error` (which we block).
	// Let's just return false.
	return false
}
func (s *sanitizedError) Timeout() bool { return false }
func (s *sanitizedError) Temporary() bool { return false }

func main() {
    baseErr := &url.Error{URL: "http://example.com/botSECRET", Err: errors.New("some error")}
    err := &sanitizedError{err: baseErr, msg: "sanitized url"}

    var t interface{ Unwrap() error }
    if errors.As(err, &t) {
        fmt.Printf("Extracted interface! Type is %T\n", t)
        fmt.Println("Unwrapped error:", t.Unwrap())
    } else {
        fmt.Println("Did not extract")
    }
}
