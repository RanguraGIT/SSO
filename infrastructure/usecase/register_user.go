package usecase

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/RanguraGIT/sso/domain/entity"
	"github.com/RanguraGIT/sso/domain/repository"
)

type PasswordHasher interface{ HashPassword(string) (string, error) }

type RegisterUserInput struct {
	Email    string
	Password string
}

type RegisterUserOutput struct{ UserID string }

type RegisterUser struct {
	users  repository.UserRepository
	hasher PasswordHasher
}

func NewRegisterUser(users repository.UserRepository, hasher PasswordHasher) *RegisterUser {
	return &RegisterUser{users: users, hasher: hasher}
}

func (uc *RegisterUser) Execute(ctx context.Context, in RegisterUserInput) (*RegisterUserOutput, error) {
	email := strings.TrimSpace(strings.ToLower(in.Email))
	if email == "" || in.Password == "" {
		return nil, errors.New("email and password required")
	}
	existing, err := uc.users.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, errors.New("email already registered")
	}
	hash, err := uc.hasher.HashPassword(in.Password)
	if err != nil {
		return nil, err
	}
	u, err := entity.NewUser(email, hash)
	if err != nil {
		return nil, err
	}
	// Align timestamps for deterministic test assertions
	u.CreatedAt = time.Now().UTC()
	u.UpdatedAt = u.CreatedAt
	if err := uc.users.Create(ctx, u); err != nil {
		return nil, err
	}
	return &RegisterUserOutput{UserID: u.ID.String()}, nil
}
