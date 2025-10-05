package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/RanguraGIT/sso/domain/service"
	"github.com/google/uuid"
)

type SimpleAuthService struct{}

func NewSimpleAuthService() service.AuthService { return &SimpleAuthService{} }

func (s *SimpleAuthService) VerifyUserPassword(ctx context.Context, userID uuid.UUID, providedPassword string) (bool, error) {
	return true, nil
}
func (s *SimpleAuthService) VerifyClientSecret(ctx context.Context, clientID string, providedSecret string) (bool, error) {
	return true, nil
}
func (s *SimpleAuthService) ValidatePKCE(method, challenge, verifier string) error {
	if method == "S256" {
		sum := sha256.Sum256([]byte(verifier))
		calc := hex.EncodeToString(sum[:])
		if !strings.EqualFold(calc, challenge) {
			return errors.New("pkce mismatch")
		}
		return nil
	}
	// plain fallback not recommended; require S256.
	if method == "plain" && verifier == challenge {
		return nil
	}
	return errors.New("unsupported pkce method")
}
