package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	dservice "github.com/RanguraGIT/sso/domain/service"
	"github.com/RanguraGIT/sso/domain/vo"
)

type JWTTokenService struct {
	keys *InMemoryKeyRotation
}

func NewJWTTokenService(keys *InMemoryKeyRotation) dservice.TokenService {
	return &JWTTokenService{keys: keys}
}

func (s *JWTTokenService) IssueAccessAndRefresh(_ context.Context, claims vo.JWTClaims, refreshTTL time.Duration) (*dservice.TokenIssueResult, error) {
	ttl := time.Until(time.Unix(claims.ExpiresAt, 0))
	if ttl <= 0 {
		return nil, errors.New("claims already expired")
	}
	priv, kid, err := s.keys.SigningKey()
	if err != nil {
		return nil, err
	}
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = kid
	token.Claims = jwt.MapClaims{
		"sub":       claims.Subject,
		"aud":       claims.Audience,
		"iss":       claims.Issuer,
		"iat":       claims.IssuedAt,
		"exp":       claims.ExpiresAt,
		"scope":     claims.Scope,
		"client_id": claims.ClientID,
		"nonce":     claims.Nonce,
	}
	signed, err := token.SignedString(priv)
	if err != nil {
		return nil, err
	}
	// Secure random 32-byte refresh token (opaque) encoded base64url (no padding).
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	refreshStr := base64.RawURLEncoding.EncodeToString(raw)
	// Store hashed identifier (full SHA-256 hex of raw token) to avoid storing the raw secret server-side.
	h := sha256.Sum256([]byte(refreshStr))
	refreshID := hex.EncodeToString(h[:])
	return &dservice.TokenIssueResult{
		AccessToken:      signed,
		RefreshToken:     refreshStr,
		AccessExpiresAt:  time.Unix(claims.ExpiresAt, 0),
		RefreshExpiresAt: time.Now().Add(refreshTTL),
		Claims:           claims,
		RefreshTokenID:   refreshID, // full hash for lookup
	}, nil
}

// IssueIDToken creates an ID Token (subset of claims; can diverge from access token claims if needed).
func (s *JWTTokenService) IssueIDToken(ctx context.Context, claims vo.JWTClaims, ttl time.Duration) (string, error) {
	priv, kid, err := s.keys.SigningKey()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	exp := now.Add(ttl).Unix()
	tok := jwt.New(jwt.SigningMethodRS256)
	tok.Header["kid"] = kid
	mc := jwt.MapClaims{
		"iss": claims.Issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"iat": now.Unix(),
		"exp": exp,
	}
	if claims.Nonce != "" {
		mc["nonce"] = claims.Nonce
	}
	// at_hash (OPTIONAL) - include when access token present; we hash later if raw access token supplied via context.
	if rawAccess, ok := ctx.Value("raw_access_token").(string); ok && rawAccess != "" {
		sum := sha256.Sum256([]byte(rawAccess))
		left := sum[:16]
		mc["at_hash"] = base64.RawURLEncoding.EncodeToString(left)
	}
	tok.Claims = mc
	return tok.SignedString(priv)
}

func (s *JWTTokenService) ValidateAccessToken(_ context.Context, tokenString string) (*vo.JWTClaims, error) {
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		// Ensure expected signing method
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected_signing_method")
		}
		kid, _ := t.Header["kid"].(string)
		// Lookup key from active or previous keys
		priv, _, err := s.keys.SigningKey() // simplistic: only active key; improvement: expose public set & match kid
		if err != nil {
			return nil, err
		}
		pub := &priv.PublicKey
		_ = kid // placeholder until multiple key lookup implemented
		return pub, nil
	}
	parsed, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid_token")
	}
	vc := vo.JWTClaims{}
	if sub, ok := claims["sub"].(string); ok {
		vc.Subject = sub
	}
	if iss, ok := claims["iss"].(string); ok {
		vc.Issuer = iss
	}
	if scope, ok := claims["scope"].(string); ok {
		vc.Scope = scope
	}
	if cid, ok := claims["client_id"].(string); ok {
		vc.ClientID = cid
	}
	return &vc, nil
}
