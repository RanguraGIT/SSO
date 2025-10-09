package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/RanguraGIT/sso/domain/entity"
	"github.com/RanguraGIT/sso/domain/repository"
	dservice "github.com/RanguraGIT/sso/domain/service"
	du "github.com/RanguraGIT/sso/domain/usecase"
	"github.com/RanguraGIT/sso/domain/vo"
)

type IssueToken struct {
	clients      repository.ClientRepository
	tokens       repository.TokenRepository
	tokenService dservice.TokenService
}

func NewIssueToken(clients repository.ClientRepository, tokens repository.TokenRepository, tokenService dservice.TokenService) *IssueToken {
	return &IssueToken{clients: clients, tokens: tokens, tokenService: tokenService}
}

func (uc *IssueToken) Execute(ctx context.Context, in du.IssueTokenInput) (*du.IssueTokenOutput, error) {
	c, err := uc.clients.GetByClientID(ctx, in.ClientID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("client not found")
	}
	now := time.Now().UTC()
	claims := vo.JWTClaims{
		Subject:   in.UserID.String(),
		Audience:  in.Audience,
		Issuer:    in.Issuer,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(in.AccessTTL).Unix(),
		Scope:     in.Scope,
		ClientID:  in.ClientID,
	}
	res, err := uc.tokenService.IssueAccessAndRefresh(ctx, claims, in.RefreshTTL)
	if err != nil {
		return nil, err
	}
	// Also issue ID token (using access token TTL for now) - future: separate ID token TTL if needed.
	// Provide access token to context for at_hash computation.
	idCtx := context.WithValue(ctx, "raw_access_token", res.AccessToken)
	idToken, err := uc.tokenService.IssueIDToken(idCtx, claims, in.AccessTTL)
	if err != nil {
		return nil, err
	}
	// Persist token metadata (split scope string by spaces)
	scopes := []string{}
	if in.Scope != "" {
		for _, s := range splitScopes(in.Scope) {
			if s != "" {
				scopes = append(scopes, s)
			}
		}
	}
	meta, err := entity.NewToken(in.UserID, c.ID, scopes, res.AccessToken, res.RefreshTokenID, time.Unix(claims.ExpiresAt, 0), res.RefreshExpiresAt)
	if err == nil {
		meta.ClientPublicID = c.ClientID
		_ = uc.tokens.Store(ctx, meta)
	}
	return &du.IssueTokenOutput{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		ExpiresIn:    int64(res.AccessExpiresAt.Sub(now).Seconds()),
		Scope:        in.Scope,
		TokenType:    "Bearer",
		IDToken:      idToken,
	}, nil
}

func splitScopes(s string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' { // separators
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
