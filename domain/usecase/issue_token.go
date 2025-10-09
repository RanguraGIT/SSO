package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type IssueTokenInput struct {
	UserID     uuid.UUID
	ClientID   string
	Scope      string
	Audience   []string
	Issuer     string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

type IssueTokenOutput struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	Scope        string
	TokenType    string
	IDToken      string
}

type IssueToken interface {
	Execute(ctx context.Context, in IssueTokenInput) (*IssueTokenOutput, error)
}
