package approval

import (
	"testing"
)

func TestComputeFingerprint_StableForSameRedactedRequest(t *testing.T) {
	host := "app01.example"
	cmd := `curl -H "Authorization: bearer sekreet" https://example.com`
	timeout := 42.0

	_, body1, fp1, err := BuildExecuteRemoteRequest(host, cmd, timeout)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest: %v", err)
	}
	_, body2, fp2, err := BuildExecuteRemoteRequest(host, cmd, timeout)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest: %v", err)
	}
	if string(body1) != string(body2) {
		t.Fatalf("canonical body mismatch: %q vs %q", body1, body2)
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprints differ: %q vs %q", fp1, fp2)
	}
}

func TestComputeFingerprint_ChangesWhenCommandChanges(t *testing.T) {
	host := "db.internal"
	timeout := 30.0

	_, _, fp1, err := BuildExecuteRemoteRequest(host, "systemctl status nginx", timeout)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest: %v", err)
	}
	_, _, fp2, err := BuildExecuteRemoteRequest(host, "systemctl restart nginx", timeout)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest: %v", err)
	}
	if fp1 == fp2 {
		t.Fatalf("expected different fingerprints, both %q", fp1)
	}
}

func TestFingerprintPrefix(t *testing.T) {
	body := []byte(`{"tool":"execute_remote","host":"h","command":"true","timeout_sec":1}`)
	fp := ComputeFingerprint(body)
	if len(fp) != 64 {
		t.Fatalf("ComputeFingerprint length = %d, want 64", len(fp))
	}
	prefix := FingerprintPrefix(fp)
	if len(prefix) != 8 {
		t.Fatalf("FingerprintPrefix length = %d, want 8", len(prefix))
	}
	if prefix != fp[:8] {
		t.Fatalf("FingerprintPrefix = %q, want %q", prefix, fp[:8])
	}
}
