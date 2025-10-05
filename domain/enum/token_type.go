package enum

// TokenType is an RFC 6749 token type enumeration (subset).
type TokenType string

const (
	AccessToken  TokenType = "access_token"
	RefreshToken TokenType = "refresh_token"
)

func (t TokenType) String() string { return string(t) }
