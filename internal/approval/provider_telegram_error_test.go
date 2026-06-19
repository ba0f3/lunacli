package approval

import (
	"errors"
	"net"
	"net/url"
	"testing"
)

type mockNetError struct{}

func (m mockNetError) Error() string   { return "mock net error" }
func (m mockNetError) Timeout() bool   { return true }
func (m mockNetError) Temporary() bool { return true }

type unwrapInterface interface {
	Unwrap() error
}

func TestSanitizedError_As(t *testing.T) {
	tg := &TelegramProvider{botToken: "SECRET"}
	inner := &url.Error{URL: "http://example.com/botSECRET", Err: errors.New("inner error")}
	wrapped := tg.sanitizeError(inner)

	t.Run("Blocks url.Error extraction", func(t *testing.T) {
		var target *url.Error
		if errors.As(wrapped, &target) {
			t.Fatalf("Expected As(*url.Error) to return false, but it extracted: %v", target)
		}
	})

	t.Run("Allows and wraps net.Error", func(t *testing.T) {
		// Mock inner error to be a net.Error
		netErrInner := &url.Error{URL: "http://example.com/botSECRET", Err: mockNetError{}}
		netWrapped := tg.sanitizeError(netErrInner)

		var target net.Error
		if !errors.As(netWrapped, &target) {
			t.Fatalf("Expected As(net.Error) to return true")
		}

		if target.Error() != netWrapped.Error() {
			t.Errorf("Extracted net.Error should have sanitized message %q, got %q", netWrapped.Error(), target.Error())
		}
		if !target.Timeout() {
			t.Errorf("Extracted net.Error.Timeout() should return true based on mockNetError")
		}
	})

	t.Run("Blocks arbitrary interface extraction", func(t *testing.T) {
		var target unwrapInterface
		if errors.As(wrapped, &target) {
			t.Fatalf("Expected As(unwrapInterface) to return false to prevent leaking *url.Error, but got true")
		}
	})

	t.Run("Redacts token string from error message", func(t *testing.T) {
		errWithMessage := errors.New("HTTP Error: bad gateway for url https://api.telegram.org/botSECRET/getUpdates")
		wrappedErr := tg.sanitizeError(errWithMessage)

		expectedMsg := "HTTP Error: bad gateway for url https://api.telegram.org/bot[REDACTED]/getUpdates"
		if wrappedErr.Error() != expectedMsg {
			t.Errorf("Expected sanitized error message %q, got %q", expectedMsg, wrappedErr.Error())
		}
	})
}
