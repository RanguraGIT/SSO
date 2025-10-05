package vo

import "errors"

// PasswordHash wraps a previously computed password hash (bcrypt/argon2/scrypt etc.).
// Keeps domain logic explicit that this is a hash (never raw password).
type PasswordHash struct{ value string }

func NewPasswordHash(v string) (PasswordHash, error) {
	if v == "" {
		return PasswordHash{}, errors.New("password hash required")
	}
	// We don't validate algorithm here to keep domain decoupled from hashing impl.
	return PasswordHash{value: v}, nil
}

func (p PasswordHash) String() string { return p.value }
