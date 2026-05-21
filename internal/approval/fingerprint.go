package approval

import (
	"crypto/sha256"
	"encoding/hex"
)

// ComputeFingerprint returns the lowercase hex-encoded SHA-256 of canonicalBody.
func ComputeFingerprint(canonicalBody []byte) string {
	sum := sha256.Sum256(canonicalBody)
	return hex.EncodeToString(sum[:])
}

// FingerprintPrefix returns the first 8 characters of fingerprint (full fingerprints are 64 hex chars).
func FingerprintPrefix(fingerprint string) string {
	if len(fingerprint) <= 8 {
		return fingerprint
	}
	return fingerprint[:8]
}
