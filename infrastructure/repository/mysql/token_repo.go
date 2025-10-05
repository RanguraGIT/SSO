package mysql

import (
	"context"
	"database/sql"

	"github.com/RanguraGIT/sso/domain/entity"
	"github.com/RanguraGIT/sso/domain/repository"
	"github.com/google/uuid"

)

type TokenRepo struct{ db *sql.DB }

func NewTokenRepo(db *sql.DB) repository.TokenRepository { return &TokenRepo{db: db} }

func (r *TokenRepo) Store(ctx context.Context, t *entity.Token) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO tokens(id,user_id,client_id,client_public_id,access_jwt,refresh_token_id,parent_refresh_id,rotated,revoked,expires_at,refresh_expires,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, t.ID.String(), nullableUUID(t.UserID), t.ClientID.String(), t.ClientPublicID, t.AccessJWT, t.RefreshTokenID, nullString(t.ParentRefreshID), t.Rotated, t.Revoked, t.ExpiresAt, t.RefreshExpires, t.CreatedAt)
	return err
}

func (r *TokenRepo) GetByRefreshID(ctx context.Context, refreshTokenID string) (*entity.Token, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id,user_id,client_id,client_public_id,access_jwt,refresh_token_id,parent_refresh_id,rotated,revoked,expires_at,refresh_expires,created_at FROM tokens WHERE refresh_token_id=?`, refreshTokenID)
	t := &entity.Token{}
	var userID, parent sql.NullString
	if err := row.Scan(&t.ID, &userID, &t.ClientID, &t.ClientPublicID, &t.AccessJWT, &t.RefreshTokenID, &parent, &t.Rotated, &t.Revoked, &t.ExpiresAt, &t.RefreshExpires, &t.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if userID.Valid {
		if uid, err := uuidParse(userID.String); err == nil {
			t.UserID = uid
		}
	}
	if parent.Valid {
		t.ParentRefreshID = parent.String
	}
	return t, nil
}

func (r *TokenRepo) RevokeByRefreshID(ctx context.Context, refreshTokenID string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE tokens SET revoked=1 WHERE refresh_token_id=?`, refreshTokenID)
	return err
}

// RevokeChain naive implementation: revoke all sharing same initial prefix (future: add parent pointer)
func (r *TokenRepo) RevokeChain(ctx context.Context, refreshTokenID string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE tokens SET revoked=1 WHERE refresh_token_id=?`, refreshTokenID)
	return err
}

// MarkRotated marks a refresh token as rotated so future reuse attempts can be detected.
func (r *TokenRepo) MarkRotated(ctx context.Context, refreshTokenID string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE tokens SET rotated=1 WHERE refresh_token_id=?`, refreshTokenID)
	return err
}

// Helpers
func nullableUUID(id uuid.UUID) interface{} {
	if id == uuid.Nil {
		return nil
	}
	return id.String()
}

func uuidParse(s string) (uuid.UUID, error) { return uuid.Parse(s) }

func nullString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
