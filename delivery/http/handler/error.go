package handler

import (
	"encoding/json"
	"net/http"
)

// OAuthError represents an RFC 6749 / OIDC style error response.
// Fields:
//
//	error:             single ASCII error code
//	error_description: human-readable description (optional)
//	error_uri:         link to documentation (optional)
//	state:             mirrors request state when present (for authorize/token flows)
type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	State            string `json:"state,omitempty"`
}

// writeOAuthError writes a JSON error body with proper headers.
func writeOAuthError(w http.ResponseWriter, status int, code, description, state string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(OAuthError{
		Error:            code,
		ErrorDescription: description,
		State:            state,
	})
}
