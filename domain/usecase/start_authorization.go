package usecase

import (
	"context"
)

type StartAuthInput struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              string
}

type StartAuthResult struct {
	Code  string
	State string
}

// StartAuthorization defines the interface for starting an OAuth authorization flow.
type StartAuthorization interface {
	Execute(ctx context.Context, in StartAuthInput) (*StartAuthResult, error)
}
