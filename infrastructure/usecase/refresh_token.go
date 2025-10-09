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

type RefreshToken struct {
	tokens       repository.TokenRepository
	clients      repository.ClientRepository
	tokenService dservice.TokenService
}

func NewRefreshToken(tokens repository.TokenRepository, clients repository.ClientRepository, tokenService dservice.TokenService) *RefreshToken {
	return &RefreshToken{tokens: tokens, clients: clients, tokenService: tokenService}
}

func (uc *RefreshToken) Execute(ctx context.Context, in du.RefreshTokenInput) (*du.RefreshTokenOutput, error) {
	if in.RefreshTokenID == "" {
		return nil, errors.New("missing refresh token id")
	}
	meta, err := uc.tokens.GetByRefreshID(ctx, in.RefreshTokenID)
	if err != nil {
		return nil, err
	}
	if meta == nil || meta.Revoked {
		return nil, errors.New("invalid_refresh_token")
	}
	if meta.Rotated { // reuse / replay detection
		_ = uc.tokens.RevokeChain(ctx, in.RefreshTokenID) // best-effort
		return nil, errors.New("refresh_token_reuse_detected")
	}
	if meta.IsRefreshExpired(time.Now().UTC()) {
		return nil, errors.New("refresh_expired")
	}
	client, err := uc.clients.GetByClientID(ctx, meta.ClientPublicID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("client_not_found")
	}

	// Build new JWT claims (same user, scopes, audience, issuer) with new expiry

	now := time.Now().UTC()
	claims := vo.JWTClaims{
		Subject:   meta.UserID.String(),
		Audience:  in.Audience,
		Issuer:    in.Issuer,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(in.AccessTTL).Unix(),
		Scope:     joinScopes(meta.Scopes),
		ClientID:  meta.ClientPublicID,
	}
	res, err := uc.tokenService.IssueAccessAndRefresh(ctx, claims, in.RefreshTTL)
	if err != nil {
		return nil, err
	}
	// Persist new token metadata with parent pointer
	newMeta, err := entity.NewToken(meta.UserID, meta.ClientID, meta.Scopes, res.AccessToken, res.RefreshTokenID, time.Unix(claims.ExpiresAt, 0), res.RefreshExpiresAt)
	if err == nil {
		newMeta.ClientPublicID = meta.ClientPublicID
		newMeta.ParentRefreshID = meta.RefreshTokenID
		_ = uc.tokens.Store(ctx, newMeta)
		_ = uc.tokens.MarkRotated(ctx, meta.RefreshTokenID) // mark old as rotated
	}
	return &du.RefreshTokenOutput{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		ExpiresIn:    int64(res.AccessExpiresAt.Sub(now).Seconds()),
		Scope:        claims.Scope,
		TokenType:    "Bearer",
	}, nil
}

func joinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	out := scopes[0]
	for i := 1; i < len(scopes); i++ {
		out += " " + scopes[i]
	}
	return out
}
