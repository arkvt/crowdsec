package hostlogstore

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	_ "modernc.org/sqlite"
)

// ProtectionLog represents a single entry from file_protection_log table.
type ProtectionLog struct {
	ID             int64
	Timestamp      string
	FilePath       string
	FileName       string
	Action         string
	Success        int64
	UnlockDuration sql.NullInt64
	ErrorMessage   sql.NullString
	UploadedAt     sql.NullString
}

// ActivityLog represents a single entry from file_activity_log table.
type ActivityLog struct {
	ID         int64
	Timestamp  string
	FilePath   string
	FileName   string
	Operation  string
	User       sql.NullString
	Process    sql.NullString
	Validation string
	IsFolder   int64
	UploadedAt sql.NullString
}

// QueryResult contains the query results and pagination info.
type QueryResult struct {
	Items       []ProtectionLog
	NextSinceID int64
	HasMore     bool
}

// ActivityQueryResult contains the query results and pagination info.
type ActivityQueryResult struct {
	Items       []ActivityLog
	NextSinceID int64
	HasMore     bool
}

// Reader provides read-only access to the host logs SQLite database.
type Reader struct {
	db     *sql.DB
	logger *log.Entry
}

// NewReader creates a new Reader with a read-only SQLite connection.
func NewReader(dbPath string, logger *log.Entry) (*Reader, error) {
	if logger == nil {
		logger = log.StandardLogger().WithField("service", "hostlogstore-reader")
	}

	dsn := buildReadOnlyDSN(dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("hostlogstore reader open db: %w", err)
	}

	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("hostlogstore reader ping: %w", err)
	}

	return &Reader{
		db:     db,
		logger: logger,
	}, nil
}

// Close closes the reader's database connection.
func (r *Reader) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// Query retrieves host logs with pagination support.
// sinceID: return records with id > sinceID (use 0 for first query)
// limit: max number of records to return (capped at 5000)
func (r *Reader) QueryProtectionLogs(ctx context.Context, sinceID int64, limit int) (*QueryResult, error) {
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}

	result := &QueryResult{Items: make([]ProtectionLog, 0)}

	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * 100 * time.Millisecond
			r.logger.WithField("attempt", attempt+1).Debug("retrying after SQLITE_BUSY")
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		result, err = r.queryProtectionOnce(ctx, sinceID, limit)
		if err == nil {
			return result, nil
		}

		if !isSQLiteBusy(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("hostlogstore protection query failed after retries: %w", err)
}

func (r *Reader) queryProtectionOnce(ctx context.Context, sinceID int64, limit int) (*QueryResult, error) {
	result := &QueryResult{Items: make([]ProtectionLog, 0, limit)}

	query := `
		SELECT id, timestamp, file_path, file_name, action, success, unlock_duration, error_message, uploaded_at
		FROM file_protection_log
		WHERE id > ?
		ORDER BY id ASC
		LIMIT ?
	`

	rows, err := r.db.QueryContext(ctx, query, sinceID, limit+1)
	if err != nil {
		return nil, fmt.Errorf("hostlogstore query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item ProtectionLog
		if err := rows.Scan(
			&item.ID,
			&item.Timestamp,
			&item.FilePath,
			&item.FileName,
			&item.Action,
			&item.Success,
			&item.UnlockDuration,
			&item.ErrorMessage,
			&item.UploadedAt,
		); err != nil {
			return nil, fmt.Errorf("hostlogstore scan: %w", err)
		}
		result.Items = append(result.Items, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("hostlogstore rows: %w", err)
	}

	if len(result.Items) > limit {
		result.HasMore = true
		result.Items = result.Items[:limit]
	}

	if len(result.Items) > 0 {
		result.NextSinceID = result.Items[len(result.Items)-1].ID
	} else {
		result.NextSinceID = sinceID
	}

	return result, nil
}

// QueryActivityLogs retrieves file activity logs with pagination support.
func (r *Reader) QueryActivityLogs(ctx context.Context, sinceID int64, limit int) (*ActivityQueryResult, error) {
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}

	result := &ActivityQueryResult{Items: make([]ActivityLog, 0)}

	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * 100 * time.Millisecond
			r.logger.WithField("attempt", attempt+1).Debug("retrying after SQLITE_BUSY")
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		result, err = r.queryActivityOnce(ctx, sinceID, limit)
		if err == nil {
			return result, nil
		}

		if !isSQLiteBusy(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("hostlogstore activity query failed after retries: %w", err)
}

func (r *Reader) queryActivityOnce(ctx context.Context, sinceID int64, limit int) (*ActivityQueryResult, error) {
	result := &ActivityQueryResult{Items: make([]ActivityLog, 0, limit)}

	query := `
		SELECT id, timestamp, file_path, file_name, operation, user, process, validation, is_folder, uploaded_at
		FROM file_activity_log
		WHERE id > ?
		ORDER BY id ASC
		LIMIT ?
	`

	rows, err := r.db.QueryContext(ctx, query, sinceID, limit+1)
	if err != nil {
		return nil, fmt.Errorf("hostlogstore activity query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item ActivityLog
		if err := rows.Scan(
			&item.ID,
			&item.Timestamp,
			&item.FilePath,
			&item.FileName,
			&item.Operation,
			&item.User,
			&item.Process,
			&item.Validation,
			&item.IsFolder,
			&item.UploadedAt,
		); err != nil {
			return nil, fmt.Errorf("hostlogstore activity scan: %w", err)
		}
		result.Items = append(result.Items, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("hostlogstore activity rows: %w", err)
	}

	if len(result.Items) > limit {
		result.HasMore = true
		result.Items = result.Items[:limit]
	}

	if len(result.Items) > 0 {
		result.NextSinceID = result.Items[len(result.Items)-1].ID
	} else {
		result.NextSinceID = sinceID
	}

	return result, nil
}

func buildReadOnlyDSN(path string) string {
	p := filepath.ToSlash(path)
	if strings.HasPrefix(p, "//") {
		p = p[1:]
	}
	return fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(5000)", p)
}

func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "SQLITE_BUSY") ||
		strings.Contains(errStr, "database is locked") ||
		strings.Contains(errStr, "busy")
}
