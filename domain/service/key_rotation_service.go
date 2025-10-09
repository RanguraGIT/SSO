package service

import (
	"context"
	"time"

	"github.com/RanguraGIT/sso/domain/vo"
)

// KeyRotationService manages active + previous signing keys and JWKS exposure.
type KeyRotationService interface {
	CurrentKeyID() string
	RotateIfNeeded(ctx context.Context) error
	GetPublicJWKS(ctx context.Context) (any, error) // Returns a JWKS representation (structure defined in infra layer)
	SignJWT(claims vo.JWTClaims, ttl time.Duration) (string, error)
}
