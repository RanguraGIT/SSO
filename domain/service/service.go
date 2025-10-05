package service

import (
	"context"
	"time"

	"github.com/RanguraGIT/sso/domain/vo"
	"github.com/google/uuid"
)

// AuthService encapsulates user & client authentication (password verify, client secret, PKCE validation).
// Security: keep cryptographic and validation logic separated from handlers for testability.
type AuthService interface {
	VerifyUserPassword(ctx context.Context, userID uuid.UUID, providedPassword string) (bool, error)
	VerifyClientSecret(ctx context.Context, clientID string, providedSecret string) (bool, error)
	ValidatePKCE(codeChallengeMethod, codeChallenge, codeVerifier string) error
}

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

// KeyRotationService manages active + previous signing keys and JWKS exposure.
type KeyRotationService interface {
	CurrentKeyID() string
	RotateIfNeeded(ctx context.Context) error
	GetPublicJWKS(ctx context.Context) (any, error) // Returns a JWKS representation (structure defined in infra layer)
	SignJWT(claims vo.JWTClaims, ttl time.Duration) (string, error)
}
