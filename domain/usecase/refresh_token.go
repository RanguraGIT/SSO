package usecase

import (
	"context"
	"time"
)

type RefreshTokenInput struct {
	RefreshTokenID string
	Issuer         string
	Audience       []string
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
}

type RefreshTokenOutput struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
	Scope        string
}

type RefreshToken interface {
	Execute(ctx context.Context, in RefreshTokenInput) (*RefreshTokenOutput, error)
}
