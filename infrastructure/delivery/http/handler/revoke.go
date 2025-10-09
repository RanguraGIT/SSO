package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/RanguraGIT/sso/domain/repository"
)

type RevokeHandler struct{ Tokens repository.TokenRepository }

func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	// Accept token or refresh_token param; accept form, query or JSON body.
	rt := r.Form.Get("refresh_token")
	if rt == "" {
		rt = r.Form.Get("token")
	}
	// If still empty, try JSON body
	if rt == "" {
		// Read body into a small buffer
		body, _ := io.ReadAll(r.Body)
		// allow subsequent handlers to not rely on body (we don't reuse r.Body here)
		if len(body) > 0 {
			var m map[string]string
			if err := json.Unmarshal(body, &m); err == nil {
				if v, ok := m["refresh_token"]; ok && v != "" {
					rt = v
				} else if v, ok := m["token"]; ok && v != "" {
					rt = v
				}
			}
		}
	}
	if strings.TrimSpace(rt) == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "missing token"})
		return
	}

	// If the client supplied the raw refresh token (opaque base64), convert to stored id via sha256 hex.
	hash := sha256.Sum256([]byte(rt))
	refreshID := hex.EncodeToString(hash[:])

	_ = h.Tokens.RevokeByRefreshID(r.Context(), refreshID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"revoked": true})
}
