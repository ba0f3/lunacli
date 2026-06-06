package approval

import (
	"strings"
	"testing"
)

func TestRedactSecrets_CommandFlags(t *testing.T) {
	input := "curl --password supersecret --token=abc123 -H Authorization: Bearer xyz"
	want := "curl --password [REDACTED] --token=[REDACTED] -H Authorization: [REDACTED] Bearer xyz"
	got := RedactSecrets(input)
	if got != want {
		t.Fatalf("RedactSecrets() = %q, want %q", got, want)
	}
}

func TestRedactSecrets_CurlAuthorizationAndUser(t *testing.T) {
	for _, input := range []string{
		`curl -u alice:secret --header "Authorization: Bearer token-value" https://example.test`,
		`curl --header="Authorization: Bearer token-value" https://example.test`,
		`curl --proxy-header="Proxy-Authorization: Basic token-value" https://example.test`,
		`curl -H"Authorization: Bearer token-value" https://example.test`,
		`curl -H Authorization:token-value https://example.test`,
		`curl -HAuthorization:token-value https://example.test`,
		`curl --user=alice:secret https://example.test`,
		`curl --proxy-user=alice:secret https://example.test`,
		`curl -ualice:secret https://example.test`,
		`curl -u "alice:secret pass" https://example.test`,
		`curl --user='alice:secret pass' https://example.test`,
		`curl -H Authorization:" Bearer token-value" https://example.test`,
		`curl https://alice:secret@example.test`,
	} {
		got := RedactSecrets(input)
		for _, secret := range []string{"alice:secret", "token-value"} {
			if strings.Contains(got, secret) {
				t.Fatalf("RedactSecrets(%q) leaked %q in %q", input, secret, got)
			}
		}
	}
}

func TestRedactSecrets_PreservesCommandAfterAuthorizationHeader(t *testing.T) {
	for _, input := range []string{
		`curl -H 'Authorization: Bearer token-value' example.com ; touch /tmp/pwned`,
		`curl -H 'Authorization: token-value'; touch /tmp/pwned`,
	} {
		got := RedactSecrets(input)
		if strings.Contains(got, "token-value") {
			t.Fatalf("RedactSecrets() leaked token in %q", got)
		}
		if !strings.Contains(got, "touch /tmp/pwned") {
			t.Fatalf("RedactSecrets() hid command suffix in %q", got)
		}
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
