package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/RanguraGIT/sso/domain/entity"
)

// SessionRepository stores browser login sessions.
type SessionRepository interface {
	Create(ctx context.Context, s *entity.Session) error
	Get(ctx context.Context, id uuid.UUID) (*entity.Session, error)
	AddClient(ctx context.Context, id uuid.UUID, clientID uuid.UUID) error
	Revoke(ctx context.Context, id uuid.UUID) error
}
