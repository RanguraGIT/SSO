package usecase

import (
	"context"

	"github.com/google/uuid"
)

type UserLoginInput struct {
	Email    string
	Password string
}

type UserLoginOutput struct{ UserID uuid.UUID }

type UserLogin interface {
	Execute(ctx context.Context, in UserLoginInput) (*UserLoginOutput, error)
}
