package security

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// FuzzMutationBypass detects if a command classified as ReadOnly can actually
// mutate the filesystem. It uses a Docker container with a read-only filesystem
// (except for a tmpfs at /tmp). If the OS kernel rejects a write syscall with
// "Read-only file system", it proves the command attempted to mutate state.
func FuzzMutationBypass(f *testing.F) {
	// Add seed corpus: all ReadOnly cases from regression tests
	for _, tc := range classifyRegressionCases {
		if tc.expected == ReadOnly {
			f.Add(tc.command)
		}
	}

	// Add some known obfuscation patterns to help the fuzzer
	seeds := []string{
		`c\at /etc/passwd`,
		`c"a"t /etc/passwd`,
		`/usr/bin/cat /etc/passwd`,
		`env cat /etc/passwd`,
		`xargs cat /etc/passwd`,
		`cat /etc/passwd | tee /etc/hacked`,
		`cat /etc/passwd > /etc/shadow`,
		`CAT /etc/passwd`,
		`Cat /etc/passwd`,
		`echo hello > /tmp/test`, // Writable, should not be a bypass
		`touch /tmp/test`,        // Writable, should not be a bypass
		`touch /etc/test`,        // Read-only, WOULD be a bypass if ReadOnly
		`rm /etc/passwd`,         // Read-only, WOULD be a bypass if ReadOnly
	}
	for _, s := range seeds {
		f.Add(s)
	}

	containerName := os.Getenv("LUNA_FUZZ_CONTAINER")

	f.Fuzz(func(t *testing.T, command string) {
		cmd := strings.TrimSpace(command)
		if len(cmd) == 0 || len(cmd) > maxCommandLen {
			return
		}

		// Phase 1: Static pre-filter
		result := Classify(cmd)
		if result.Class != ReadOnly {
			// It was correctly identified as Mutating or Forbidden.
			// No bypass is possible here.
			return
		}

		// Phase 2: Runtime execution probe
		if containerName == "" {
			// Skip docker exec phase if not running in the harness
			return
		}

		// Execute the command in the read-only sandbox container
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		dockerCmd := exec.CommandContext(ctx, "docker", "exec", containerName, "sh", "-c", cmd)
		var stderr bytes.Buffer
		dockerCmd.Stderr = &stderr

		err := dockerCmd.Run()

		// We only care if it failed with a write-rejection
		if err != nil {
			errStr := stderr.String()

			// Detect write syscall rejections
			isWriteRejection := strings.Contains(errStr, "Read-only file system") ||
				(strings.Contains(errStr, "Operation not permitted") && isWriteContext(cmd)) ||
				(strings.Contains(errStr, "Permission denied") && isWriteContext(cmd)) ||
				strings.Contains(errStr, "cannot create")

			if isWriteRejection {
				t.Errorf("BYPASS DETECTED:\nCommand classified as ReadOnly: %q\nStderr: %s", cmd, errStr)
			}
		}
	})
}

// isWriteContext is a simple heuristic to check if the error is likely from
// a write attempt rather than a read attempt (like reading /etc/shadow).
// Since the entire FS is read-only, "Read-only file system" is the primary signal,
// but for Permission denied we need to be more careful to avoid false positives.
func isWriteContext(cmd string) bool {
	lower := strings.ToLower(cmd)
	if strings.Contains(lower, ">") ||
		strings.Contains(lower, "chmod ") ||
		strings.Contains(lower, "chown ") ||
		strings.Contains(lower, "rm ") ||
		strings.Contains(lower, "touch ") ||
		strings.Contains(lower, "mkdir ") ||
		strings.Contains(lower, "cp ") ||
		strings.Contains(lower, "mv ") {
		return true
	}
	return false
}
