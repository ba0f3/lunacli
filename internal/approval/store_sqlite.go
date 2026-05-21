package approval

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

type sqliteStore struct {
	db *sql.DB
}

// OpenSQLiteStore opens (or creates) an approvals database at path.
func OpenSQLiteStore(path string) (Store, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	_, statErr := os.Stat(path)
	isNewDB := errors.Is(statErr, fs.ErrNotExist)
	if statErr != nil && !isNewDB {
		return nil, statErr
	}

	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	s := &sqliteStore{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if isNewDB {
		if err := os.Chmod(path, 0o600); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return s, nil
}

func sqliteDSN(path string) string {
	// Busy timeout avoids transient "database locked" flakes under parallel tests/tools.
	const opts = "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	return "file:" + path + opts
}

func (s *sqliteStore) migrate() error {
	init := `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS approvals (
	id TEXT PRIMARY KEY NOT NULL,
	tool TEXT NOT NULL,
	host TEXT NOT NULL,
	redacted_command TEXT NOT NULL,
	normalized_body BLOB NOT NULL,
	classification TEXT NOT NULL,
	reason TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	status TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	decided_at TEXT,
	approver TEXT NOT NULL,
	redaction_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	approval_id TEXT NOT NULL,
	event_type TEXT NOT NULL,
	detail TEXT NOT NULL,
	created_at TEXT NOT NULL,
	FOREIGN KEY (approval_id) REFERENCES approvals(id) ON DELETE CASCADE
);
`
	if _, err := s.db.Exec(init); err != nil {
		return err
	}
	return s.migrateColumns()
}

func (s *sqliteStore) migrateColumns() error {
	// Ignore "duplicate column" errors when upgrading existing databases.
	for _, stmt := range []string{
		`ALTER TABLE approvals ADD COLUMN telegram_chat_id INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE approvals ADD COLUMN telegram_message_id INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	return nil
}

func (s *sqliteStore) InsertPending(r Record) error {
	if r.Status != StatusPending {
		return fmt.Errorf("InsertPending requires status pending, got %q", r.Status)
	}
	_, err := s.db.Exec(`
INSERT INTO approvals (
	id, tool, host, redacted_command, normalized_body, classification, reason,
	fingerprint, status, created_at, expires_at, decided_at, approver, redaction_version
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
`, r.ID, r.Tool, r.Host, r.RedactedCommand, r.NormalizedBody, r.Classification, r.Reason,
		r.Fingerprint, string(r.Status), r.CreatedAt.UTC().Format(time.RFC3339Nano),
		r.ExpiresAt.UTC().Format(time.RFC3339Nano), nilOrRFC3339Nano(r.DecidedAt), r.Approver,
		r.RedactionVersion)
	return err
}

func (s *sqliteStore) Get(id string) (Record, error) {
	row := s.db.QueryRow(`
SELECT id, tool, host, redacted_command, normalized_body, classification, reason,
	fingerprint, status, created_at, expires_at, decided_at, approver, redaction_version,
	telegram_chat_id, telegram_message_id
FROM approvals WHERE id = ?
`, id)
	r, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	return r, nil
}

func (s *sqliteStore) ListPending() ([]Record, error) {
	rows, err := s.db.Query(`
SELECT id, tool, host, redacted_command, normalized_body, classification, reason,
	fingerprint, status, created_at, expires_at, decided_at, approver, redaction_version,
	telegram_chat_id, telegram_message_id
FROM approvals WHERE status = ?
ORDER BY created_at ASC
`, StatusPending)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *sqliteStore) UpdateStatus(id string, status Status, approver string, decidedAt time.Time) error {
	decidedAt = decidedAt.UTC()
	res, err := s.db.Exec(`
UPDATE approvals SET status = ?, approver = ?, decided_at = ?
WHERE id = ?
`, string(status), approver, decidedAt.Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStore) MarkConsumed(id string, _ time.Time) error {
	res, err := s.db.Exec(`UPDATE approvals SET status = ? WHERE id = ?`, StatusConsumed, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStore) ExpireDue(now time.Time) error {
	now = now.UTC()
	ts := now.Format(time.RFC3339Nano)
	_, err := s.db.Exec(`
UPDATE approvals SET status = ?, decided_at = ?, approver = ?
WHERE status = ? AND expires_at < ?
`, StatusExpired, ts, "", StatusPending, ts)
	return err
}

func (s *sqliteStore) SetTelegramMessage(id string, chatID, messageID int64) error {
	res, err := s.db.Exec(`
UPDATE approvals SET telegram_chat_id = ?, telegram_message_id = ?
WHERE id = ?
`, chatID, messageID, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStore) AppendAudit(e AuditEvent) error {
	_, err := s.db.Exec(`
INSERT INTO audit_events (approval_id, event_type, detail, created_at)
VALUES (?,?,?,?)
`, e.ApprovalID, e.EventType, e.Detail, e.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecord(row rowScanner) (Record, error) {
	var (
		id, tool, host, cmd, classification, reason, fingerprint, status string
		normalized                                                       []byte
		created                                                          sql.NullString
		expires                                                          sql.NullString
		decided                                                          sql.NullString
		approver                                                         string
		redVer                                                           string
		tgChat, tgMsg                                                    int64
	)
	if err := row.Scan(
		&id, &tool, &host, &cmd, &normalized, &classification, &reason,
		&fingerprint, &status, &created, &expires, &decided, &approver, &redVer,
		&tgChat, &tgMsg); err != nil {
		return Record{}, err
	}
	if !created.Valid {
		return Record{}, fmt.Errorf("missing created_at")
	}
	if !expires.Valid {
		return Record{}, fmt.Errorf("missing expires_at")
	}
	createdTM, err := time.Parse(time.RFC3339Nano, created.String)
	if err != nil {
		return Record{}, fmt.Errorf("parse created_at: %w", err)
	}
	expiresTM, err := time.Parse(time.RFC3339Nano, expires.String)
	if err != nil {
		return Record{}, fmt.Errorf("parse expires_at: %w", err)
	}

	var decidedPtr *time.Time
	if decided.Valid && decided.String != "" {
		tm, err := time.Parse(time.RFC3339Nano, decided.String)
		if err != nil {
			return Record{}, fmt.Errorf("parse decided_at: %w", err)
		}
		tmu := tm.UTC()
		decidedPtr = &tmu
	}

	return Record{
		ID:               id,
		Tool:             tool,
		Host:             host,
		RedactedCommand:  cmd,
		NormalizedBody:   normalized,
		Classification:   classification,
		Reason:           reason,
		Fingerprint:      fingerprint,
		Status:           Status(status),
		CreatedAt:        createdTM.UTC(),
		ExpiresAt:        expiresTM.UTC(),
		DecidedAt:        decidedPtr,
		Approver:          approver,
		RedactionVersion:  redVer,
		TelegramChatID:    tgChat,
		TelegramMessageID: tgMsg,
	}, nil
}

func nilOrRFC3339Nano(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}
