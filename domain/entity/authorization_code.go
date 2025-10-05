package entity

import (
	"errors"
	"time"
)

// AuthorizationCode represents a short-lived OAuth2 authorization code.
// It binds a client, user, redirect URI and PKCE challenge (if provided).
type AuthorizationCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               []string
	CodeChallenge       string
	CodeChallengeMethod string // "S256" or "plain" (plain discouraged)
	ExpiresAt           time.Time
	Used                bool
	CreatedAt           time.Time
}

func NewAuthorizationCode(code, clientID, userID, redirectURI string, scope []string, challenge, method string, ttl time.Duration) (*AuthorizationCode, error) {
	if code == "" || clientID == "" || userID == "" || redirectURI == "" {
		return nil, errors.New("missing required fields for authorization code")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	return &AuthorizationCode{
		Code: code, ClientID: clientID, UserID: userID, RedirectURI: redirectURI,
		Scope: scope, CodeChallenge: challenge, CodeChallengeMethod: method,
		ExpiresAt: now.Add(ttl), CreatedAt: now,
	}, nil
}

func (c *AuthorizationCode) IsExpired() bool { return time.Now().UTC().After(c.ExpiresAt) }
