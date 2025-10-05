package handler

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"time"

	dservice "github.com/RanguraGIT/sso/domain/service"
)

type JWKSHandler struct{ Keys dservice.KeyRotationService }

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	jwks, err := h.Keys.GetPublicJWKS(r.Context())
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Unable to load JWKS", "")
		return
	}
	// Compute weak ETag based on hash of JSON payload.
	b, _ := json.Marshal(jwks)
	sum := sha256.Sum256(b)
	etag := "W/\"" + b64url(sum[:8]) + "\"" // short hash for brevity
	// If-None-Match handling
	if inm := r.Header.Get("If-None-Match"); inm != "" && inm == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.Write(b)
}

// b64url encodes without padding.
func b64url(b []byte) string { return jsonBase64Raw(b) }

// jsonBase64Raw is a tiny helper to avoid importing base64 again here if already elsewhere; re-implement lightweight.
// Re-implement base64.RawURLEncoding.EncodeToString to keep file self-contained.
// NOTE: For production, import encoding/base64; kept minimal here.
func jsonBase64Raw(b []byte) string {
	const encode = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, 0, (len(b)*8+5)/6)
	var val uint32
	var bits uint
	for _, by := range b {
		val = (val << 8) | uint32(by)
		bits += 8
		for bits >= 6 {
			bits -= 6
			out = append(out, encode[(val>>bits)&0x3F])
		}
	}
	if bits > 0 {
		out = append(out, encode[(val<<(6-bits))&0x3F])
	}
	return string(out)
}
