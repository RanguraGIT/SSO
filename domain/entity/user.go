package entity

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// User represents an identity in the system (end-user / resource owner).
// Pure domain object: no persistence or transport concerns.
type User struct {
	ID           uuid.UUID
	Email        string // Will be wrapped by value object in aggregate/usecases
	PasswordHash string // Stored hash (argon2/bcrypt/etc). Raw password never stored.
	CreatedAt    time.Time
	UpdatedAt    time.Time
	// Security flags
	EmailVerified bool
	Locked        bool
}

func NewUser(email, passwordHash string) (*User, error) {
	if email == "" {
		return nil, errors.New("email required")
	}
	if passwordHash == "" {
		return nil, errors.New("password hash required")
	}
	return &User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}, nil
}

func (u *User) Touch() { u.UpdatedAt = time.Now().UTC() }
