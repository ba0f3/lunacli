package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditLogger(t *testing.T) {
	tmp, err := os.MkdirTemp("", "luna-audit-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	logFile := filepath.Join(tmp, "audit.jsonl")
	l := NewLogger(logFile)

	ev := Event{
		Event:          "command_executed",
		Host:           "10.0.0.1",
		Command:        "uptime",
		Classification: "read-only",
		Source:         "mcp",
	}

	if err := l.Log(ev); err != nil {
		t.Fatalf("failed to log: %v", err)
	}

	f, err := os.Open(logFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		var readEv Event
		if err := json.Unmarshal(scanner.Bytes(), &readEv); err != nil {
			t.Fatal(err)
		}
		if readEv.Event != "command_executed" || readEv.Host != "10.0.0.1" {
			t.Errorf("unexpected logged event: %+v", readEv)
		}
	}
}
