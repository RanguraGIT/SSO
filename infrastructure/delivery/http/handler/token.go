package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/RanguraGIT/sso/domain/repository"
	"github.com/RanguraGIT/sso/domain/usecase"
	"github.com/google/uuid"
)

type TokenHandler struct {
	Issue   usecase.IssueToken
	Refresh usecase.RefreshToken
	Codes   repository.AuthorizationCodeRepository
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Malformed form body", "")
		return
	}
	grantType := r.Form.Get("grant_type")
	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCode(w, r)
	case "refresh_token":
		h.handleRefreshToken(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Grant type not supported", "")
	}
}

func (h *TokenHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	raw := r.Form.Get("refresh_token")
	clientID := r.Form.Get("client_id")
	if raw == "" || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing refresh_token or client_id", "")
		return
	}
	// Hash the provided refresh token (base64url) with SHA-256 hex to obtain stored identifier.
	hash := sha256.Sum256([]byte(raw))
	refreshID := hex.EncodeToString(hash[:])
	out, err := h.Refresh.Execute(r.Context(), usecase.RefreshTokenInput{
		RefreshTokenID: refreshID,
		Issuer:         issuerFromRequest(r),
		Audience:       []string{clientID},
		AccessTTL:      10 * time.Minute,
		RefreshTTL:     24 * time.Hour,
	})
	if err != nil {
		// Avoid leaking internal SQL / system errors: map to generic messages unless recognized.
		desc := "refresh token invalid or expired"
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "reuse") || strings.Contains(lower, "rotated") {
			desc = "refresh token reuse detected"
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", desc, "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  out.AccessToken,
		"refresh_token": out.RefreshToken,
		"token_type":    out.TokenType,
		"expires_in":    out.ExpiresIn,
		"scope":         out.Scope,
	})
}

func (h *TokenHandler) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	codeVerifier := r.Form.Get("code_verifier")
	if code == "" || clientID == "" || redirectURI == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing code, client_id or redirect_uri", "")
		return
	}
	ac, err := h.Codes.Get(r.Context(), code)
	if err != nil || ac == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Authorization code invalid", "")
		return
	}
	if ac.Used || ac.IsExpired() {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Authorization code expired or already used", "")
		return
	}
	if ac.ClientID != clientID || ac.RedirectURI != redirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Redirect URI or client mismatch", "")
		return
	}
	// PKCE validation
	if ac.CodeChallenge != "" {
		if err := verifyPKCE(ac.CodeChallengeMethod, ac.CodeChallenge, codeVerifier); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE validation failed", "")
			return
		}
	}
	// Mark used (best-effort; if fails we still continue for demo)
	_ = h.Codes.MarkUsed(r.Context(), code)

	userUUID := deriveUserUUID(ac.UserID)
	scopeStr := strings.Join(ac.Scope, " ")
	out, err := h.Issue.Execute(r.Context(), usecase.IssueTokenInput{
		UserID:     userUUID,
		ClientID:   clientID,
		Scope:      scopeStr,
		Audience:   []string{clientID},
		Issuer:     issuerFromRequest(r),
		AccessTTL:  10 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error(), "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  out.AccessToken,
		"refresh_token": out.RefreshToken,
		"token_type":    out.TokenType,
		"expires_in":    out.ExpiresIn,
		"scope":         out.Scope,
		"id_token":      out.IDToken,
	})
}

func verifyPKCE(method, challenge, verifier string) error {
	if challenge == "" {
		return nil
	}
	if verifier == "" {
		return errors.New("missing verifier")
	}
	switch method {
	case "", "plain":
		if challenge != verifier {
			return errors.New("pkce plain mismatch")
		}
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		calc := base64.RawURLEncoding.EncodeToString(sum[:])
		if calc != challenge {
			return errors.New("pkce s256 mismatch")
		}
	default:
		return errors.New("unsupported pkce method")
	}
	return nil
}

// deriveUserUUID turns stored string user id into UUID if possible; otherwise zero UUID (demo simplification).
func deriveUserUUID(id string) uuid.UUID {
	if u, err := uuid.Parse(id); err == nil {
		return u
	}
	// Deterministic hash fallback for demo (NOT for production): just return a fixed UUID.
	fixed, _ := uuid.Parse("00000000-0000-0000-0000-000000000001")
	return fixed
}

func issuerFromRequest(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
