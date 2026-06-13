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

type interfaceWithTimeout interface {
    Timeout() bool
}

func main() {
    baseErr := &url.Error{URL: "http://example.com/botSECRET", Err: errors.New("some error")}
    err := &sanitizedError{err: baseErr, msg: "sanitized url"}

    var t interfaceWithTimeout
    if errors.As(err, &t) {
        fmt.Printf("Extracted interface! Type is %T\n", t)
        if errVal, ok := t.(error); ok {
            fmt.Println("Error string:", errVal.Error())
        }
    }
}
