package handler

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/RanguraGIT/sso/domain/usecase"
	req "github.com/RanguraGIT/sso/infrastructure/delivery/http/request"
	resp "github.com/RanguraGIT/sso/infrastructure/delivery/http/response"
)

type LoginHandler struct {
	LoginUC   usecase.UserLogin
	SessionUC usecase.CreateSession
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body req.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		resp.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	loginOut, err := h.LoginUC.Execute(r.Context(), usecase.UserLoginInput{Email: body.Email, Password: body.Password})
	if err != nil {
		log.Printf("login: auth failed email=%s err=%v", body.Email, err)
		resp.JSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	ip := extractIP(r.RemoteAddr)
	sessOut, err := h.SessionUC.Execute(r.Context(), usecase.CreateSessionInput{UserID: loginOut.UserID, TTL: 8 * time.Hour, IP: ip, UA: r.UserAgent()})
	if err != nil {
		log.Printf("login: session create failed user=%s err=%v", loginOut.UserID, err)
		resp.JSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
		return
	}
	cookie := &http.Cookie{Name: "sid", Value: sessOut.SessionID.String(), Path: "/", HttpOnly: true, Secure: false, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(8 * time.Hour)}
	// NOTE: Secure: true recommended behind HTTPS; left false for local dev.
	http.SetCookie(w, cookie)
	resp.JSON(w, http.StatusOK, map[string]string{"session_id": sessOut.SessionID.String(), "user_id": loginOut.UserID.String()})
}

// Helper to parse UUID cookie (might be used by authorize refactor)
func sessionIDFromCookie(r *http.Request) (uuid.UUID, error) {
	c, err := r.Cookie("sid")
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(c.Value)
}

// extractIP strips port from remote address if present.
func extractIP(remote string) string {
	if remote == "" {
		return remote
	}
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	// Fallback: remove last colon segment for IPv4:port
	if i := strings.LastIndex(remote, ":"); i > 0 {
		return remote[:i]
	}
	return remote
}
