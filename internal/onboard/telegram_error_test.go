package onboard

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
	inner := &url.Error{URL: "http://example.com/botSECRET", Err: errors.New("inner error")}
	wrapped := sanitizeTokenError(inner, "SECRET")

	t.Run("Blocks url.Error extraction", func(t *testing.T) {
		var target *url.Error
		if errors.As(wrapped, &target) {
			t.Fatalf("Expected As(*url.Error) to return false, but it extracted: %v", target)
		}
	})

	t.Run("Allows and wraps net.Error", func(t *testing.T) {
		// Mock inner error to be a net.Error
		netErrInner := &url.Error{URL: "http://example.com/botSECRET", Err: mockNetError{}}
		netWrapped := sanitizeTokenError(netErrInner, "SECRET")

		var target net.Error
		if !errors.As(netWrapped, &target) {
			t.Fatalf("Expected As(net.Error) to return true")
		}

		// Check that the extracted net.Error is actually our sanitized wrapper,
		// and it successfully delegates Timeout() and Temporary()
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
}
