package vo

import "errors"

// RefreshTokenID is an opaque identifier (usually a hash of the refresh token value) used for rotation & revocation.
type RefreshTokenID struct{ value string }

func NewRefreshTokenID(v string) (RefreshTokenID, error) {
	if v == "" {
		return RefreshTokenID{}, errors.New("refresh token id required")
	}
	return RefreshTokenID{value: v}, nil
}

func (r RefreshTokenID) String() string { return r.value }
