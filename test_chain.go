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
    if uErr, ok := s.err.(*url.Error); ok {
        return errors.As(uErr.Err, target)
    }
	return errors.As(s.err, target)
}

func main() {
	inner := &url.Error{URL: "http://example.com/botSECRET", Err: errors.New("inner error")}
	wrapped := fmt.Errorf("wrapped error: %w", inner)
	e := &sanitizedError{err: wrapped, msg: "sanitized url"}

	var unwrap interface{ Unwrap() error }
	if errors.As(e, &unwrap) {
		fmt.Printf("Extracted! Type: %T\n", unwrap)
		if u, ok := unwrap.(*url.Error); ok {
			fmt.Println("Leaked URL:", u.URL)
		}
	}
}
