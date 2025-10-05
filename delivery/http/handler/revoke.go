package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/RanguraGIT/sso/domain/repository"
)

// RevokeHandler handles RFC7009 style token revocation (idempotent 200 response).
// For refresh tokens we revoke the specific token (and optionally its chain if rotation misuse).
type RevokeHandler struct {
	Tokens repository.TokenRepository
}

func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Malformed form body", "")
		return
	}
	token := r.Form.Get("token")
	if token != "" && h.Tokens != nil {
		hashBytes := sha256.Sum256([]byte(token))
		id := hex.EncodeToString(hashBytes[:])
		_ = h.Tokens.RevokeByRefreshID(r.Context(), id) // best-effort
	}
	// Always 200 per spec (even if unknown/invalid)
	w.WriteHeader(http.StatusOK)
}
