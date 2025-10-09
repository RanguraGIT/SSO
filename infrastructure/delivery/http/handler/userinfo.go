package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/RanguraGIT/sso/domain/repository"
	dservice "github.com/RanguraGIT/sso/domain/service"
	"github.com/google/uuid"
)

type UserInfoHandler struct {
	Users        repository.UserRepository
	TokenService dservice.TokenService
}

func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract Bearer token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "Missing authorization header", "")
		return
	}

	parts := strings.Fields(authHeader)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "Invalid authorization header format", "")
		return
	}

	accessToken := parts[1]

	// Validate and parse the access token
	claims, err := h.TokenService.ValidateAccessToken(r.Context(), accessToken)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "Access token invalid or expired", "")
		return
	}

	// Parse user ID from subject claim
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "Invalid subject in token", "")
		return
	}

	// Fetch user from database
	user, err := h.Users.GetByID(r.Context(), userID)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to retrieve user", "")
		return
	}
	if user == nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "User not found", "")
		return
	}

	// Build OIDC standard userinfo response
	response := map[string]any{
		"sub":   user.ID.String(),
		"email": user.Email,
	}

	// Add email_verified if available
	if user.EmailVerified {
		response["email_verified"] = true
	} else {
		response["email_verified"] = false
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
