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

type leakInterface interface {
    Timeout() bool
}

func main() {
    baseErr := &url.Error{URL: "http://example.com/botSECRET", Err: errors.New("some error")}
    err := &sanitizedError{err: baseErr, msg: "sanitized url"}

    var targetErr *url.Error
    if errors.As(err, &targetErr) {
        fmt.Println("Leaked url.Error:", targetErr.URL)
    } else {
        fmt.Println("Did not leak url.Error")
    }

	var myTarget leakInterface
	if errors.As(err, &myTarget) {
		if urlErr, ok := myTarget.(*url.Error); ok {
            fmt.Println("Leaked url.Error through interface:", urlErr.URL)
        } else {
            fmt.Printf("Leaked leakInterface, but it's not url.Error: %T\n", myTarget)
        }
	} else {
		fmt.Println("Did not leak leakInterface")
	}
}
