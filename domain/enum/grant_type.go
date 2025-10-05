package enum

import "fmt"

type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeClientCredentials GrantType = "client_credentials"
	// (Future) refresh_token grant handled separately (rotation constraints) but we include constant.
	GrantTypeRefreshToken GrantType = "refresh_token"
)

func (g GrantType) String() string { return string(g) }

func ParseGrantType(v string) (GrantType, error) {
	switch v {
	case string(GrantTypeAuthorizationCode):
		return GrantTypeAuthorizationCode, nil
	case string(GrantTypeClientCredentials):
		return GrantTypeClientCredentials, nil
	case string(GrantTypeRefreshToken):
		return GrantTypeRefreshToken, nil
	default:
		return "", fmt.Errorf("unsupported grant type: %s", v)
	}
}
