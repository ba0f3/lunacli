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

	// We need to implement As to delegate down the chain, but SKIP any *url.Error we find,
	// because *url.Error might satisfy the target interface and get extracted, leaking the URL.

	// How does errors.As work under the hood?
	// It unwraps the error and checks if the current error is assignable to target.
	// Since we can't control errors.As unwrapping, we must do the unwrapping ourselves
	// and skip *url.Error.

	err := s.err
	for err != nil {
		if uErr, ok := err.(*url.Error); ok {
			err = uErr.Err // Skip *url.Error but continue with its underlying error
			continue
		}

		// To check if `err` is assignable to `target`, we can just call errors.As(err, target),
		// BUT wait, errors.As(err, target) will ALSO unwrap `err` automatically, which we don't want
		// if it encounters a *url.Error deeper down.
		// Wait, if we just do errors.As(err, target) and the chain has another *url.Error, it will leak.

        // Actually, url.Error is almost always the outermost error for net/http errors!
        // But let's be safe. If we return false, it means we don't support `As` for arbitrary targets.
        // What do we actually need As for? Probably just net.Error so we can do .Timeout()
        // Let's just return false after checking **url.Error and *net.Error.
	}
	return false
}
func (s *sanitizedError) Timeout() bool { return false }
func (s *sanitizedError) Temporary() bool { return false }

func main() {}
