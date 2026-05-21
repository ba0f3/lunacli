package approval

import (
	"errors"
	"testing"
)

func TestAuthorizeCLIApprover_AllowsConfiguredUID(t *testing.T) {
	if err := AuthorizeCLIApprover("42", "0,42,1000"); err != nil {
		t.Fatalf("AuthorizeCLIApprover(\"42\") error = %v, want nil", err)
	}
}

func TestAuthorizeCLIApprover_TrimsSpaces(t *testing.T) {
	if err := AuthorizeCLIApprover("1000", " 1000 , 42 "); err != nil {
		t.Fatalf("AuthorizeCLIApprover error = %v, want nil", err)
	}
}

func TestAuthorizeCLIApprover_RejectsUnknownUID(t *testing.T) {
	if err := AuthorizeCLIApprover("999", "0"); err == nil {
		t.Fatal("expected error for uid not listed")
	} else if !errors.Is(err, ErrCLIApproverForbidden) {
		t.Fatalf("AuthorizeCLIApprover error = %v, want wrapped %v", err, ErrCLIApproverForbidden)
	}
}

func TestAuthorizeCLIApprover_RejectsWhenEmpty(t *testing.T) {
	err := AuthorizeCLIApprover("0", "")
	if err == nil {
		t.Fatal("expected error when allow list is empty")
	}
	if !errors.Is(err, ErrCLIApproverForbidden) {
		t.Fatalf("error = %v, want wrapped %v", err, ErrCLIApproverForbidden)
	}
}
