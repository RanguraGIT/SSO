package usecase

import (
	"context"
	"errors"

	"github.com/RanguraGIT/sso/domain/repository"
	dservice "github.com/RanguraGIT/sso/domain/service"
	"github.com/google/uuid"
)

type UserLoginInput struct {
	Email    string
	Password string
}

type UserLoginOutput struct {
	UserID uuid.UUID
}

type UserLogin struct {
	users repository.UserRepository
	auth  dservice.AuthService
}

func NewUserLogin(users repository.UserRepository, auth dservice.AuthService) *UserLogin {
	return &UserLogin{users: users, auth: auth}
}

func (uc *UserLogin) Execute(ctx context.Context, in UserLoginInput) (*UserLoginOutput, error) {
	u, err := uc.users.GetByEmail(ctx, in.Email)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, errors.New("invalid credentials")
	}
	ok, err := uc.auth.VerifyUserPassword(ctx, u.ID, in.Password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid credentials")
	}
	return &UserLoginOutput{UserID: u.ID}, nil
}
