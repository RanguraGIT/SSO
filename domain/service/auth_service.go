package service

import (
	"context"

	"github.com/google/uuid"
)

// AuthService encapsulates user & client authentication (password verify, client secret, PKCE validation).
// Security: keep cryptographic and validation logic separated from handlers for testability.
type AuthService interface {
	VerifyUserPassword(ctx context.Context, userID uuid.UUID, providedPassword string) (bool, error)
	VerifyClientSecret(ctx context.Context, clientID string, providedSecret string) (bool, error)
	ValidatePKCE(codeChallengeMethod, codeChallenge, codeVerifier string) error
}
