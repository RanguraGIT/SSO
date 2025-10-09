package repository

import (
	"context"

	"github.com/RanguraGIT/sso/domain/entity"
)

// AuthorizationCodeRepository stores short-lived authorization codes produced by /authorize.
// Codes are one-time use and expire quickly (e.g., 5-10 minutes).
type AuthorizationCodeRepository interface {
	Create(ctx context.Context, c *entity.AuthorizationCode) error
	Get(ctx context.Context, code string) (*entity.AuthorizationCode, error)
	MarkUsed(ctx context.Context, code string) error
}
