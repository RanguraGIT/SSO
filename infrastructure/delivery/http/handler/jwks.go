package handler

import (
	"encoding/json"
	"net/http"

	"github.com/RanguraGIT/sso/domain/service"
)

type JWKSHandler struct{ Keys service.KeyRotationService }

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Attempt to fetch cached JWKS from service; fall back to empty.
	ctx := r.Context()
	_ = h.Keys.RotateIfNeeded(ctx)
	jwks, err := h.Keys.GetPublicJWKS(ctx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": "failed to fetch jwks"})
		return
	}
	json.NewEncoder(w).Encode(jwks)
}
