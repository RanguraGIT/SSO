package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/RanguraGIT/sso/domain/entity"
	"github.com/RanguraGIT/sso/domain/repository"
	du "github.com/RanguraGIT/sso/domain/usecase"
	"github.com/google/uuid"
)

type CreateSession struct{ sessions repository.SessionRepository }

func NewCreateSession(sessions repository.SessionRepository) *CreateSession {
	return &CreateSession{sessions: sessions}
}

func (uc *CreateSession) Execute(ctx context.Context, in du.CreateSessionInput) (*du.CreateSessionOutput, error) {
	if in.UserID == uuid.Nil {
		return nil, errors.New("userID required")
	}
	if in.TTL <= 0 {
		in.TTL = 8 * time.Hour
	}
	sess, err := entity.NewSession(in.UserID, in.TTL, in.IP, in.UA)
	if err != nil {
		return nil, err
	}
	if err := uc.sessions.Create(ctx, sess); err != nil {
		return nil, err
	}
	return &du.CreateSessionOutput{SessionID: sess.ID}, nil
}
