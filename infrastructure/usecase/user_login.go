package usecase

import (
	"context"
	"errors"

	"github.com/RanguraGIT/sso/domain/repository"
	dservice "github.com/RanguraGIT/sso/domain/service"
	du "github.com/RanguraGIT/sso/domain/usecase"
)

type UserLogin struct {
	users repository.UserRepository
	auth  dservice.AuthService
}

func NewUserLogin(users repository.UserRepository, auth dservice.AuthService) *UserLogin {
	return &UserLogin{users: users, auth: auth}
}

func (uc *UserLogin) Execute(ctx context.Context, in du.UserLoginInput) (*du.UserLoginOutput, error) {
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
	return &du.UserLoginOutput{UserID: u.ID}, nil
}
