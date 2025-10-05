package handler

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/RanguraGIT/sso/infrastructure/usecase"
	"github.com/google/uuid"
)

type LoginHandler struct {
	LoginUC   *usecase.UserLogin
	SessionUC *usecase.CreateSession
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	loginOut, err := h.LoginUC.Execute(r.Context(), usecase.UserLoginInput{Email: req.Email, Password: req.Password})
	if err != nil {
		log.Printf("login: auth failed email=%s err=%v", req.Email, err)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	ip := extractIP(r.RemoteAddr)
	sessOut, err := h.SessionUC.Execute(r.Context(), usecase.CreateSessionInput{UserID: loginOut.UserID, TTL: 8 * time.Hour, IP: ip, UA: r.UserAgent()})
	if err != nil {
		log.Printf("login: session create failed user=%s err=%v", loginOut.UserID, err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{Name: "sid", Value: sessOut.SessionID.String(), Path: "/", HttpOnly: true, Secure: false, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(8 * time.Hour)}
	// NOTE: Secure: true recommended behind HTTPS; left false for local dev.
	http.SetCookie(w, cookie)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"session_id": sessOut.SessionID.String(), "user_id": loginOut.UserID.String()})
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
