package repository

import (
	"context"

	"github.com/RanguraGIT/sso/domain/entity"
)

// ClientRepository handles OAuth client persistence.
type ClientRepository interface {
	GetByClientID(ctx context.Context, clientID string) (*entity.Client, error)
	Create(ctx context.Context, c *entity.Client) error
	Update(ctx context.Context, c *entity.Client) error
}
