package persistence

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Migrate executes idempotent table creation. Later we can replace with goose or atlas.
func Migrate(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id CHAR(36) PRIMARY KEY,
			email VARCHAR(255) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			email_verified TINYINT(1) NOT NULL DEFAULT 0,
			locked TINYINT(1) NOT NULL DEFAULT 0,
			created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
			updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

		`CREATE TABLE IF NOT EXISTS clients (
			id CHAR(36) PRIMARY KEY,
			client_id VARCHAR(128) NOT NULL UNIQUE,
			name VARCHAR(255) NOT NULL,
			hashed_secret VARCHAR(255) NULL,
			redirect_uris TEXT NOT NULL,
			scopes TEXT NOT NULL,
			confidential TINYINT(1) NOT NULL DEFAULT 0,
			pkce_required TINYINT(1) NOT NULL DEFAULT 1,
			created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
			updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

		`CREATE TABLE IF NOT EXISTS authorization_codes (
			code VARCHAR(255) PRIMARY KEY,
			client_id VARCHAR(128) NOT NULL,
			user_id VARCHAR(64) NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT NULL,
			code_challenge TEXT NULL,
			code_challenge_method VARCHAR(10) NULL,
			expires_at TIMESTAMP(6) NOT NULL,
			used TINYINT(1) NOT NULL DEFAULT 0,
			created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
			INDEX (client_id),
			INDEX (user_id),
			INDEX (expires_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

		`CREATE TABLE IF NOT EXISTS tokens (
			id CHAR(36) PRIMARY KEY,
			user_id CHAR(36) NULL,
			client_id CHAR(36) NOT NULL,
			client_public_id VARCHAR(128) NOT NULL,
			access_jwt TEXT NOT NULL,
			refresh_token_id VARCHAR(255) NOT NULL,
			parent_refresh_id VARCHAR(255) NULL,
			rotated TINYINT(1) NOT NULL DEFAULT 0,
			revoked TINYINT(1) NOT NULL DEFAULT 0,
			expires_at TIMESTAMP(6) NOT NULL,
			refresh_expires TIMESTAMP(6) NOT NULL,
			created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
			INDEX (client_id),
			INDEX (user_id),
			INDEX (refresh_token_id),
			INDEX (parent_refresh_id),
			INDEX (expires_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

		`CREATE TABLE IF NOT EXISTS sessions (
			id CHAR(36) PRIMARY KEY,
			user_id CHAR(36) NOT NULL,
			client_ids TEXT NULL,
			ip VARCHAR(64) NULL,
			user_agent TEXT NULL,
			expires_at TIMESTAMP(6) NOT NULL,
			revoked TINYINT(1) NOT NULL DEFAULT 0,
			created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
			INDEX (user_id),
			INDEX (expires_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,
	}

	for i, stmt := range stmts {
		if err := execRetry(ctx, db, stmt, 3); err != nil {
			return fmt.Errorf("migration %d failed: %w", i, err)
		}
	}

	// Post-migration patch: ensure sessions.client_ids exists (for older deployments)
	if err := ensureSessionClientIDsColumn(ctx, db); err != nil {
		return fmt.Errorf("ensure sessions.client_ids: %w", err)
	}
	if err := ensureTokensIDColumn(ctx, db); err != nil {
		return fmt.Errorf("ensure tokens.id: %w", err)
	}
	return nil
}

func execRetry(ctx context.Context, db *sql.DB, stmt string, attempts int) error {
	var last error
	for i := 0; i < attempts; i++ {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			last = err
			if isRetryable(err) {
				time.Sleep(time.Duration(i+1) * 150 * time.Millisecond)
				continue
			}
			return err
		}
		return nil
	}
	return last
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	// Naive detection; can expand based on driver errors.
	return strings.Contains(err.Error(), "deadlock") || strings.Contains(err.Error(), "timeout")
}

// Helper to truncate tables during tests (not used in production paths yet)
func TruncateAll(ctx context.Context, db *sql.DB) error {
	stmts := []string{"SET FOREIGN_KEY_CHECKS=0", "TRUNCATE TABLE users", "TRUNCATE TABLE clients", "TRUNCATE TABLE authorization_codes", "TRUNCATE TABLE tokens", "TRUNCATE TABLE sessions", "SET FOREIGN_KEY_CHECKS=1"}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

var ErrNotFound = errors.New("not found")

// ensureSessionClientIDsColumn adds client_ids column if missing (legacy schema upgrade helper).
func ensureSessionClientIDsColumn(ctx context.Context, db *sql.DB) error {
	// Check information_schema for column existence
	const q = `SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='sessions' AND COLUMN_NAME='client_ids'`
	var count int
	if err := db.QueryRowContext(ctx, q).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	// Add column
	_, err := db.ExecContext(ctx, `ALTER TABLE sessions ADD COLUMN client_ids TEXT NULL AFTER user_id`)
	return err
}

// ensureTokensIDColumn adds id column (primary key) if legacy table created without it.
func ensureTokensIDColumn(ctx context.Context, db *sql.DB) error {
	const check = `SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='tokens' AND COLUMN_NAME='id'`
	var count int
	if err := db.QueryRowContext(ctx, check).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	// Add column as first; populate with UUIDs for existing rows.
	if _, err := db.ExecContext(ctx, `ALTER TABLE tokens ADD COLUMN id CHAR(36) FIRST`); err != nil {
		return err
	}
	// Backfill missing ids where NULL or empty (if any rows exist)
	rows, err := db.QueryContext(ctx, `SELECT refresh_token_id FROM tokens WHERE id='' OR id IS NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var refreshID string
		if err := rows.Scan(&refreshID); err != nil {
			return err
		}
		// Best-effort deterministic placeholder using refreshID substring if length >= 36; else generate UUID()
		uid := uuid.New().String()
		if len(refreshID) >= 36 {
			uid = refreshID[:36]
		}
		if _, err := db.ExecContext(ctx, `UPDATE tokens SET id=? WHERE refresh_token_id=?`, uid, refreshID); err != nil {
			return err
		}
	}
	// Finally add primary key if not exists
	if _, err := db.ExecContext(ctx, `ALTER TABLE tokens ADD PRIMARY KEY (id)`); err != nil {
		return err
	}
	return nil
}
