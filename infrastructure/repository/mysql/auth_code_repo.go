package mysql

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/RanguraGIT/sso/domain/entity"
	"github.com/RanguraGIT/sso/domain/repository"
)

type AuthCodeRepo struct{ db *sql.DB }

func NewAuthCodeRepo(db *sql.DB) repository.AuthorizationCodeRepository { return &AuthCodeRepo{db: db} }

func (r *AuthCodeRepo) Create(ctx context.Context, c *entity.AuthorizationCode) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO authorization_codes(code,client_id,user_id,redirect_uri,scope,code_challenge,code_challenge_method,expires_at,used,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`, c.Code, c.ClientID, c.UserID, c.RedirectURI, strings.Join(c.Scope, " "), c.CodeChallenge, c.CodeChallengeMethod, c.ExpiresAt, c.Used, c.CreatedAt)
	return err
}

func (r *AuthCodeRepo) Get(ctx context.Context, code string) (*entity.AuthorizationCode, error) {
	row := r.db.QueryRowContext(ctx, `SELECT code,client_id,user_id,redirect_uri,scope,code_challenge,code_challenge_method,expires_at,used,created_at FROM authorization_codes WHERE code=?`, code)
	c := &entity.AuthorizationCode{}
	var scopeStr string
	if err := row.Scan(&c.Code, &c.ClientID, &c.UserID, &c.RedirectURI, &scopeStr, &c.CodeChallenge, &c.CodeChallengeMethod, &c.ExpiresAt, &c.Used, &c.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if strings.TrimSpace(scopeStr) != "" {
		c.Scope = strings.Fields(scopeStr)
	}
	return c, nil
}

func (r *AuthCodeRepo) MarkUsed(ctx context.Context, code string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE authorization_codes SET used=1 WHERE code=?`, code)
	return err
}

// Optionally purge expired codes (can be called on a timer)
func (r *AuthCodeRepo) PurgeExpired(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM authorization_codes WHERE expires_at < ? OR (used=1 AND created_at < ?)`, time.Now().UTC(), time.Now().UTC().Add(-10*time.Minute))
	return err
}
