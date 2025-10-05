package entity

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Token represents an issued OAuth2 / OIDC token pair metadata (access + refresh).
// Actual JWT string may be stored separately or reconstructed; refresh token (opaque) tracked for rotation.
type Token struct {
	ID              uuid.UUID
	UserID          uuid.UUID // Optional for client creds (may be zero UUID)
	ClientID        uuid.UUID
	ClientPublicID  string // Public client identifier (e.g., "app123")
	Scopes          []string
	AccessJWT       string // Signed JWT string (short-lived)
	RefreshTokenID  string // Opaque identifier (hash of refresh token) for rotation tracking
	ParentRefreshID string // Points to the refresh token this was rotated from (for chain tracking)
	Rotated         bool   // True if this refresh token has been rotated (used for reuse detection)
	ExpiresAt       time.Time
	RefreshExpires  time.Time
	Revoked         bool
	CreatedAt       time.Time
}

func NewToken(userID, clientID uuid.UUID, scopes []string, accessJWT, refreshTokenID string, expiresAt, refreshExpires time.Time) (*Token, error) {
	if clientID == uuid.Nil {
		return nil, errors.New("clientID required")
	}
	if accessJWT == "" {
		return nil, errors.New("access JWT required")
	}
	if refreshTokenID == "" {
		return nil, errors.New("refresh token id required")
	}
	return &Token{
		ID:             uuid.New(),
		UserID:         userID,
		ClientID:       clientID,
		Scopes:         scopes,
		AccessJWT:      accessJWT,
		RefreshTokenID: refreshTokenID,
		ExpiresAt:      expiresAt,
		RefreshExpires: refreshExpires,
		CreatedAt:      time.Now().UTC(),
	}, nil
}

func (t *Token) IsExpired(now time.Time) bool        { return now.After(t.ExpiresAt) }
func (t *Token) IsRefreshExpired(now time.Time) bool { return now.After(t.RefreshExpires) }
