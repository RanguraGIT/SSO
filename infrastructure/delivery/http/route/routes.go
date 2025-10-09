package route

import (
	"net/http"

	"github.com/RanguraGIT/sso/domain/repository"
	dsvc "github.com/RanguraGIT/sso/domain/service"
	du "github.com/RanguraGIT/sso/domain/usecase"
	handler "github.com/RanguraGIT/sso/infrastructure/delivery/http/handler"
)

// RegisterRoutes wires HTTP endpoints to handler implementations. It accepts domain wrappers
// so the wiring remains independent of concrete infra implementations.
func RegisterRoutes(mux *http.ServeMux, uc du.UsecaseWrapper, authCodes repository.AuthorizationCodeRepository, sessions repository.SessionRepository, users repository.UserRepository, tokens repository.TokenRepository, svcs dsvc.ServiceWrapper, issuer string) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.Handle("/.well-known/openid-configuration", &handler.DiscoveryHandler{Issuer: issuer})
	mux.Handle("/authorize", &handler.AuthorizeHandler{Start: uc.StartAuth, Sessions: sessions})
	mux.Handle("/register", &handler.RegisterHandler{UC: uc.RegisterUser})
	mux.Handle("/login", &handler.LoginHandler{LoginUC: uc.UserLogin, SessionUC: uc.CreateSess})
	mux.Handle("/jwks.json", &handler.JWKSHandler{Keys: svcs.KeyRotationService})
	mux.Handle("/token", &handler.TokenHandler{Issue: uc.IssueToken, Refresh: uc.Refresh, Codes: authCodes})
	mux.Handle("/userinfo", &handler.UserInfoHandler{Users: users, TokenService: svcs.TokenService})
	mux.Handle("/revoke", &handler.RevokeHandler{Tokens: tokens})

	// debug and root left to callers to register if desired
}
