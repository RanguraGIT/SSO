package usecase

import (
	"context"
)

type RegisterUserInput struct {
	Email    string
	Password string
}

type RegisterUserOutput struct{ UserID string }

type RegisterUser interface {
	Execute(ctx context.Context, in RegisterUserInput) (*RegisterUserOutput, error)
}
