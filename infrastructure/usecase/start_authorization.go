package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/RanguraGIT/sso/domain/entity"
	"github.com/RanguraGIT/sso/domain/repository"
	du "github.com/RanguraGIT/sso/domain/usecase"
)

type StartAuthorization struct {
	clients repository.ClientRepository
	codes   repository.AuthorizationCodeRepository
}

func NewStartAuthorization(clients repository.ClientRepository, codes repository.AuthorizationCodeRepository) *StartAuthorization {
	return &StartAuthorization{clients: clients, codes: codes}
}

func (uc *StartAuthorization) Execute(ctx context.Context, in du.StartAuthInput) (*du.StartAuthResult, error) {
	if in.ResponseType != "code" {
		return nil, errors.New("unsupported response_type")
	}
	cli, err := uc.clients.GetByClientID(ctx, in.ClientID)
	if err != nil || cli == nil {
		return nil, errors.New("invalid client_id")
	}
	// Basic redirect URI check
	allowed := false
	for _, u := range cli.RedirectURIs {
		if u == in.RedirectURI {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, errors.New("invalid redirect_uri")
	}
	// TODO: Validate scopes subset
	code, err := generateCode()
	if err != nil {
		return nil, err
	}
	scopeSlice := []string{}
	if strings.TrimSpace(in.Scope) != "" {
		scopeSlice = strings.Fields(in.Scope)
	}
	c, err := entity.NewAuthorizationCode(code, in.ClientID, in.UserID, in.RedirectURI, scopeSlice, in.CodeChallenge, in.CodeChallengeMethod, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	if err := uc.codes.Create(ctx, c); err != nil {
		return nil, err
	}
	return &du.StartAuthResult{Code: code, State: in.State}, nil
}

func generateCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
