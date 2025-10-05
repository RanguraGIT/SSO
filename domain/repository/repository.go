package repository

import (
	"context"

	"github.com/RanguraGIT/sso/domain/entity"
	"github.com/google/uuid"
)

// UserRepository defines persistence operations for users.
type UserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*entity.User, error)
	GetByEmail(ctx context.Context, email string) (*entity.User, error)
	Create(ctx context.Context, u *entity.User) error
	Update(ctx context.Context, u *entity.User) error
}

// ClientRepository handles OAuth client persistence.
type ClientRepository interface {
	GetByClientID(ctx context.Context, clientID string) (*entity.Client, error)
	Create(ctx context.Context, c *entity.Client) error
	Update(ctx context.Context, c *entity.Client) error
}

// TokenRepository stores issued access/refresh token metadata.
type TokenRepository interface {
	Store(ctx context.Context, t *entity.Token) error
	GetByRefreshID(ctx context.Context, refreshTokenID string) (*entity.Token, error)
	RevokeByRefreshID(ctx context.Context, refreshTokenID string) error
	RevokeChain(ctx context.Context, refreshTokenID string) error // Revoke this and descendant rotated tokens
	// MarkRotated marks a refresh token as having been rotated (i.e., a child issued). Enables reuse detection.
	MarkRotated(ctx context.Context, refreshTokenID string) error
}

// SessionRepository stores browser login sessions.
type SessionRepository interface {
	Create(ctx context.Context, s *entity.Session) error
	Get(ctx context.Context, id uuid.UUID) (*entity.Session, error)
	AddClient(ctx context.Context, id uuid.UUID, clientID uuid.UUID) error
	Revoke(ctx context.Context, id uuid.UUID) error
}

// AuthorizationCodeRepository stores short-lived authorization codes produced by /authorize.
// Codes are one-time use and expire quickly (e.g., 5-10 minutes).
type AuthorizationCodeRepository interface {
	Create(ctx context.Context, c *entity.AuthorizationCode) error
	Get(ctx context.Context, code string) (*entity.AuthorizationCode, error)
	MarkUsed(ctx context.Context, code string) error
}
