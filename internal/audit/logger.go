package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Event struct {
	Timestamp      string `json:"timestamp"`
	Event          string `json:"event"`
	Host           string `json:"host,omitempty"`
	Command        string `json:"command,omitempty"`
	Classification string `json:"classification,omitempty"`
	ExitCode       int    `json:"exit_code,omitempty"`
	DurationMs     int64  `json:"duration_ms,omitempty"`
	ApprovalID     string `json:"approval_id,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Source         string `json:"source"`
}

type Logger struct {
	mu       sync.Mutex
	filePath string
}

func NewLogger(filePath string) *Logger {
	return &Logger{filePath: filePath}
}

func (l *Logger) Log(ev Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	ev.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "%s\n", string(data))

	if l.filePath != "" {
		f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, _ = f.Write(data)
		_, _ = f.Write([]byte("\n"))
	}
	return nil
}
