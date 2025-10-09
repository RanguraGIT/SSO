package repository

import (
	"context"

	"github.com/RanguraGIT/sso/domain/entity"
)

// TokenRepository stores issued access/refresh token metadata.
type TokenRepository interface {
	Store(ctx context.Context, t *entity.Token) error
	GetByRefreshID(ctx context.Context, refreshTokenID string) (*entity.Token, error)
	RevokeByRefreshID(ctx context.Context, refreshTokenID string) error
	// Revoke this and descendant rotated tokens in a chain.
	RevokeChain(ctx context.Context, refreshTokenID string) error
	// MarkRotated marks a refresh token as having been rotated (i.e., a child issued). Enables reuse detection.
	MarkRotated(ctx context.Context, refreshTokenID string) error
}
