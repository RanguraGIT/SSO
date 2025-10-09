package handler

import (
	"log"
	"net/http"
	"time"

	"github.com/RanguraGIT/sso/domain/repository"
	"github.com/RanguraGIT/sso/domain/usecase"
	"github.com/google/uuid"
)

type AuthorizeHandler struct {
	Start    usecase.StartAuthorization
	Sessions repository.SessionRepository
}

// For now returns JSON instead of redirect for easier testing. Later will 302 to redirect_uri with code & state.
func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	userID := ""
	if c, err := r.Cookie("sid"); err == nil {
		if sid, err := uuid.Parse(c.Value); err == nil && h.Sessions != nil {
			sess, _ := h.Sessions.Get(r.Context(), sid)
			if sess != nil && !sess.Revoked && !sess.IsExpired(time.Now().UTC()) {
				userID = sess.UserID.String()
			}
		}
	}
	if userID == "" { // require authenticated session for now
		writeOAuthError(w, http.StatusUnauthorized, "login_required", "End-user authentication required", q.Get("state"))
		return
	}
	in := usecase.StartAuthInput{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		UserID:              userID,
	}
	res, err := h.Start.Execute(r.Context(), in)
	if err != nil {
		log.Printf("authorize error: %v", err)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error(), q.Get("state"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"code":"` + res.Code + `","state":"` + res.State + `"}`))
}
