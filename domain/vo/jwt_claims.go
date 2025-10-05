package vo

import "time"

// JWTClaims minimal domain representation of claims we care about (subset of OIDC / custom fields).
// Keep primitive to avoid coupling to a specific JWT library, enabling pure domain testing.
type JWTClaims struct {
	Subject   string
	Audience  []string
	Issuer    string
	IssuedAt  int64
	ExpiresAt int64
	Scope     string // space-delimited scopes per RFC 6749
	ClientID  string
	Nonce     string
}

func (c JWTClaims) IsExpired(now time.Time) bool {
	if c.ExpiresAt == 0 {
		return false
	}
	return now.Unix() >= c.ExpiresAt
}
