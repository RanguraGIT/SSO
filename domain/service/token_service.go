package service

import (
	"context"
	"time"

	"github.com/RanguraGIT/sso/domain/vo"
)

// TokenIssueResult returned by TokenService issue operations.
type TokenIssueResult struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	Claims           vo.JWTClaims
	RefreshTokenID   string // hashed/opaque id
	IDToken          string // OIDC ID Token (optional; set for authorization_code flow)
}

// TokenService creates & validates signed JWT access tokens and manages refresh rotation meta.
type TokenService interface {
	IssueAccessAndRefresh(ctx context.Context, claims vo.JWTClaims, refreshTTL time.Duration) (*TokenIssueResult, error)
	ValidateAccessToken(ctx context.Context, tokenString string) (*vo.JWTClaims, error)
	IssueIDToken(ctx context.Context, claims vo.JWTClaims, ttl time.Duration) (string, error)
}
