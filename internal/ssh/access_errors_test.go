package ssh

import (
	"strings"
	"testing"
)

func TestFormatAccessError_Denied(t *testing.T) {
	err := ErrAccessDenied
	got := FormatAccessError(Target{Raw: "u@h:22"}, err)
	if !strings.HasPrefix(got, "ACCESS_DENIED:") {
		t.Fatalf("got %q", got)
	}
}

func TestAccessErrorMessage_Sentinel(t *testing.T) {
	got := AccessErrorMessage(ErrAccessDenied)
	if !strings.HasPrefix(got, "ACCESS_DENIED:") {
		t.Fatalf("got %q", got)
	}
}
