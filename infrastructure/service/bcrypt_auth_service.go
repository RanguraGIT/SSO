package service

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/RanguraGIT/sso/domain/repository"
	"github.com/RanguraGIT/sso/domain/service"
	"github.com/google/uuid"
)

// BcryptAuthService implements password verification using bcrypt and the user repository.
// It does not perform timing attack mitigations beyond bcrypt cost; later add constant-time email existence checks.
type BcryptAuthService struct {
	users repository.UserRepository
	cost  int
}

func NewBcryptAuthService(users repository.UserRepository, cost int) service.AuthService {
	if cost <= 0 {
		cost = bcrypt.DefaultCost
	}
	return &BcryptAuthService{users: users, cost: cost}
}

func (s *BcryptAuthService) VerifyUserPassword(ctx context.Context, userID uuid.UUID, providedPassword string) (bool, error) {
	if userID == uuid.Nil {
		return false, errors.New("userID required")
	}
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}
	if u == nil {
		return false, errors.New("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(providedPassword)); err != nil {
		return false, nil
	}
	return true, nil
}

func (s *BcryptAuthService) VerifyClientSecret(ctx context.Context, clientID string, providedSecret string) (bool, error) {
	// Client secret verification delegated elsewhere (not implemented yet)
	return true, nil
}

func (s *BcryptAuthService) ValidatePKCE(method, challenge, verifier string) error {
	// Reuse logic from SimpleAuthService for now (duplicate small logic to avoid dependency)
	if challenge == "" {
		return nil
	}
	method = strings.ToUpper(method)
	if method == "PLAIN" && challenge == verifier {
		return nil
	}
	// Only plain handled here; S256 validated in handler/service pipeline (future refactor)
	return errors.New("unsupported pkce method")
}

// HashPassword is helper for registration use case.
func (s *BcryptAuthService) HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), s.cost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
