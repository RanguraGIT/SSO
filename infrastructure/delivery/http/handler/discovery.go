package handler

import (
	"encoding/json"
	"net/http"
)

type DiscoveryHandler struct{ Issuer string }

func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                 h.Issuer,
		"jwks_uri":               h.Issuer + "/jwks.json",
		"authorization_endpoint": h.Issuer + "/authorize",
		"token_endpoint":         h.Issuer + "/token",
		"userinfo_endpoint":      h.Issuer + "/userinfo",
	})
}
