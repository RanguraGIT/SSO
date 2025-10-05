package handler

import (
	"encoding/json"
	"net/http"
)

type DiscoveryHandler struct {
	Issuer string
}

func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                h.Issuer,
		"authorization_endpoint":                h.Issuer + "/authorize",
		"token_endpoint":                        h.Issuer + "/token",
		"userinfo_endpoint":                     h.Issuer + "/userinfo",
		"jwks_uri":                              h.Issuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "none"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}
