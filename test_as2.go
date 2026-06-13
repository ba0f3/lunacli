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
    // We want to skip delegating to url.Error since it implements interfaces that would leak it
    if uErr, ok := s.err.(*url.Error); ok {
        return errors.As(uErr.Err, target)
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

func main() {
	var e error = &sanitizedError{err: &url.Error{URL: "http://example.com/botSECRET", Err: errors.New("inner error")}, msg: "sanitized url"}

	// Let's see what happens if someone tries to extract the original error type
	var uErr *url.Error
	if errors.As(e, &uErr) {
		fmt.Println("Leaked url.Error!", uErr.URL)
	} else {
		fmt.Println("Did not leak url.Error")
	}

	var unw interface{ Unwrap() error }
	if errors.As(e, &unw) {
		fmt.Println("Extracted unwrapInterface! Type is", fmt.Sprintf("%T", unw))
		// let's see if this leaks URL
		if ue, ok := unw.(*url.Error); ok {
			fmt.Println("Leaked url.Error through interface:", ue.URL)
		}
	} else {
		fmt.Println("Did not leak unwrapInterface")
	}
}
