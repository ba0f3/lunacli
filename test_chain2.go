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
	// Walk the error chain ourselves.
	// We want to skip *url.Error instances and not delegate directly to them,
	// but we STILL want to delegate to everything else.

	// BUT wait, errors.As() handles unwrapping. If we just return errors.As(s.err, target),
	// errors.As checks if s.err is assignable to target. If target is an interface, it checks
	// if s.err implements it.

	// A simpler fix: If we are calling errors.As(s.err, target), and target is an interface type,
	// it might extract the *url.Error because *url.Error implements many interfaces.
	// Is there a way to safely unwrap without exposing url.Error?

	err := s.err
	for err != nil {
		if uErr, ok := err.(*url.Error); ok {
			err = uErr.Err
			continue
		}

		// If we just do errors.As(err, target), we will extract the current err if it matches.
		// Wait, errors.As will continue down the chain!
		// So if we do errors.As(s.err, target), errors.As will check s.err, then s.err.Unwrap(), etc.
		// If s.err.Unwrap() returns a *url.Error, errors.As will check if *url.Error matches target.
		// If target is an interface, it will match and return true, setting target to *url.Error.
		// This means we CANNOT use errors.As(s.err, target) at all.
		return false
	}
	return false
}

func (s *sanitizedError) Timeout() bool { return false }
func (s *sanitizedError) Temporary() bool { return false }

func main() {
}
