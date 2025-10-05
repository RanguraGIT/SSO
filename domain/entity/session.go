package entity

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Session represents a browser-based login session (for authorization endpoint UI or consent screens).
// Can bind to refresh token chains for additional security.
type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ClientIDs []uuid.UUID // Clients authorized within this session
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool
	IP        string
	UserAgent string
}

func NewSession(userID uuid.UUID, ttl time.Duration, ip, ua string) (*Session, error) {
	if userID == uuid.Nil {
		return nil, errors.New("userID required")
	}
	if ttl <= 0 {
		return nil, errors.New("ttl must be positive")
	}
	now := time.Now().UTC()
	return &Session{
		ID:        uuid.New(),
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		IP:        ip,
		UserAgent: ua,
	}, nil
}

func (s *Session) IsExpired(now time.Time) bool { return now.After(s.ExpiresAt) }
