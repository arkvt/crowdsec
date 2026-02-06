package hostlogstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Command struct {
	ID        string
	Type      string
	Params    json.RawMessage
	CreatedAt time.Time
	ExpiresAt time.Time
}

type CommandAck struct {
	CommandID  string
	Status     string
	Result     json.RawMessage
	Error      string
	ExecutedAt time.Time
}

type CommandStore struct {
	db *sql.DB
}

func NewCommandStore(dbPath string) (*CommandStore, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("db path is required")
	}
	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, err
	}
	conn, err := sql.Open("sqlite", buildCommandDSN(absPath))
	if err != nil {
		return nil, fmt.Errorf("hostlogstore command store open db: %w", err)
	}
	conn.SetMaxOpenConns(2)
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(5 * time.Minute)
	if err := applyPragmas(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	store := &CommandStore{db: conn}
	if err := store.init(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return store, nil
}

func (s *CommandStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *CommandStore) init() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS host_command_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command_id TEXT NOT NULL UNIQUE,
            command_type TEXT NOT NULL,
            params_json TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            status TEXT NOT NULL DEFAULT 'pending'
        )`,
		`CREATE INDEX IF NOT EXISTS idx_host_command_status ON host_command_queue(status)`,
		`CREATE INDEX IF NOT EXISTS idx_host_command_created ON host_command_queue(created_at)`,
		`CREATE TABLE IF NOT EXISTS host_command_ack (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command_id TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            result_json TEXT,
            error_message TEXT,
            executed_at TEXT NOT NULL
        )`,
	}
	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (s *CommandStore) Enqueue(ctx context.Context, cmd Command) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("host command store not initialized")
	}
	params := ""
	if len(cmd.Params) > 0 {
		params = string(cmd.Params)
	}
	createdAt := cmd.CreatedAt.UTC().Format(time.RFC3339)
	expiresAt := ""
	if !cmd.ExpiresAt.IsZero() {
		expiresAt = cmd.ExpiresAt.UTC().Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO host_command_queue (command_id, command_type, params_json, created_at, expires_at, status)
        VALUES (?, ?, ?, ?, ?, 'pending')
        ON CONFLICT(command_id) DO NOTHING
    `, cmd.ID, cmd.Type, params, createdAt, expiresAt)
	return err
}

func (s *CommandStore) WaitAck(ctx context.Context, commandID string, timeout time.Duration) (CommandAck, error) {
	deadline := time.Now().Add(timeout)
	for {
		ack, err := s.getAck(ctx, commandID)
		if err == nil {
			return ack, nil
		}
		if err != sql.ErrNoRows {
			return CommandAck{}, err
		}
		if time.Now().After(deadline) {
			return CommandAck{}, fmt.Errorf("ack timeout")
		}
		select {
		case <-ctx.Done():
			return CommandAck{}, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s *CommandStore) getAck(ctx context.Context, commandID string) (CommandAck, error) {
	var ack CommandAck
	var result sql.NullString
	var errMsg sql.NullString
	var executedAt string
	row := s.db.QueryRowContext(ctx, `
        SELECT command_id, status, result_json, error_message, executed_at
        FROM host_command_ack
        WHERE command_id = ?
        ORDER BY id DESC
        LIMIT 1
    `, commandID)
	if err := row.Scan(&ack.CommandID, &ack.Status, &result, &errMsg, &executedAt); err != nil {
		return CommandAck{}, err
	}
	if result.Valid && result.String != "" {
		ack.Result = json.RawMessage(result.String)
	}
	if errMsg.Valid {
		ack.Error = errMsg.String
	}
	if t, err := time.Parse(time.RFC3339, executedAt); err == nil {
		ack.ExecutedAt = t
	}
	return ack, nil
}

func applyPragmas(conn *sql.DB) error {
	queries := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
	}
	for _, q := range queries {
		if _, err := conn.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func buildCommandDSN(path string) string {
	p := filepath.ToSlash(path)
	if strings.HasPrefix(p, "//") {
		p = p[1:]
	}
	return fmt.Sprintf("file:%s?cache=shared&_pragma=busy_timeout(5000)", p)
}
