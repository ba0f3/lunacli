package approval

import "testing"

func TestRedactSecrets_CommandFlags(t *testing.T) {
	input := "curl --password supersecret --token=abc123 -H Authorization: Bearer xyz"
	want := "curl --password [REDACTED] --token=[REDACTED] -H Authorization: Bearer xyz"
	got := RedactSecrets(input)
	if got != want {
		t.Fatalf("RedactSecrets() = %q, want %q", got, want)
	}
}

func TestRedactSecrets_EnvAssignment(t *testing.T) {
	input := "export AWS_SECRET_ACCESS_KEY=secret"
	want := "export AWS_SECRET_ACCESS_KEY=[REDACTED]"
	got := RedactSecrets(input)
	if got != want {
		t.Fatalf("RedactSecrets() = %q, want %q", got, want)
	}
}
