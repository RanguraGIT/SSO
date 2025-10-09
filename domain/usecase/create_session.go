package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type CreateSessionInput struct {
	UserID uuid.UUID
	TTL    time.Duration
	IP     string
	UA     string
}

type CreateSessionOutput struct{ SessionID uuid.UUID }

type CreateSession interface {
	Execute(ctx context.Context, in CreateSessionInput) (*CreateSessionOutput, error)
}
