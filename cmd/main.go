package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	h "github.com/RanguraGIT/sso/delivery/http/handler"
	"github.com/RanguraGIT/sso/domain/entity"
	"github.com/RanguraGIT/sso/domain/repository"
	"github.com/RanguraGIT/sso/infrastructure/persistence"
	mysqlrepo "github.com/RanguraGIT/sso/infrastructure/repository/mysql"
	iservice "github.com/RanguraGIT/sso/infrastructure/service"
	"github.com/RanguraGIT/sso/infrastructure/usecase"
	"github.com/joho/godotenv"
)

// Temporary placeholder server until full DI wiring & routes are implemented.
// This lets you run `go run ./cmd` and have a basic health endpoint.
func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ---------- Infrastructure wiring (MySQL only) ----------
	if os.Getenv("USE_MYSQL") != "1" {
		log.Println("[warn] USE_MYSQL not set to 1; proceeding with MySQL using default env values anyway (in-memory support removed)")
	}
	var userRepo repository.UserRepository
	var clientRepo repository.ClientRepository
	var tokenRepo repository.TokenRepository
	var authCodeRepo repository.AuthorizationCodeRepository
	var sessionRepo repository.SessionRepository
	log.Println("initializing MySQL repositories (memory repositories removed)")
	db, err := persistence.OpenMySQL()
	if err != nil {
		log.Fatalf("mysql open failed: %v", err)
	}
	if err := persistence.Migrate(ctx, db); err != nil {
		log.Fatalf("migrate failed: %v", err)
	}
	userRepo = mysqlrepo.NewUserRepo(db)
	clientRepo = mysqlrepo.NewClientRepo(db)
	tokenRepo = mysqlrepo.NewTokenRepo(db)
	authCodeRepo = mysqlrepo.NewAuthCodeRepo(db)
	sessionRepo = mysqlrepo.NewSessionRepo(db)
	log.Printf("repo-types: user=%T client=%T token=%T authCode=%T session=%T", userRepo, clientRepo, tokenRepo, authCodeRepo, sessionRepo)

	keyRotation := iservice.NewInMemoryKeyRotation(12 * time.Hour)
	tokenService := iservice.NewJWTTokenService(keyRotation)
	bcryptAuth := iservice.NewBcryptAuthService(userRepo, 12)
	loginUC := usecase.NewUserLogin(userRepo, bcryptAuth)
	createSessionUC := usecase.NewCreateSession(sessionRepo)
	registerUC := usecase.NewRegisterUser(userRepo, bcryptAuth.(interface{ HashPassword(string) (string, error) }))

	// Seed demo client & user (IDs deterministic for demo) - in real system use proper creation flows.
	seedDemo(userRepo, clientRepo)

	issueTokenUC := usecase.NewIssueToken(clientRepo, tokenRepo, tokenService)
	startAuthUC := usecase.NewStartAuthorization(clientRepo, authCodeRepo)
	refreshTokenUC := usecase.NewRefreshToken(tokenRepo, clientRepo, tokenService)
	// userLoginUC := usecase.NewUserLogin(userRepo, authService) // Would be used by /authorize when password login form is added.

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	issuer := "http://localhost:8080" // TODO: derive from config / request / X-Forwarded headers
	mux.Handle("/.well-known/openid-configuration", &h.DiscoveryHandler{Issuer: issuer})
	mux.Handle("/authorize", &h.AuthorizeHandler{Start: startAuthUC, Sessions: sessionRepo})
	mux.Handle("/register", &h.RegisterHandler{UC: registerUC})
	mux.Handle("/login", &h.LoginHandler{LoginUC: loginUC, SessionUC: createSessionUC})
	mux.Handle("/jwks.json", &h.JWKSHandler{Keys: keyRotation})
	mux.Handle("/token", &h.TokenHandler{Issue: issueTokenUC, Refresh: refreshTokenUC, Codes: authCodeRepo})
	mux.Handle("/userinfo", &h.UserInfoHandler{Users: userRepo, TokenService: tokenService})
	mux.Handle("/revoke", &h.RevokeHandler{Tokens: tokenRepo})

	// Debug endpoint to confirm which repository implementations are active.
	mux.HandleFunc("/debug/repos", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"use_mysql":true,"user":"%T","client":"%T","token":"%T","auth_code":"%T","session":"%T"}`,
			userRepo, clientRepo, tokenRepo, authCodeRepo, sessionRepo)
	})

	// Catch-all (must remain last registration); discovery path should match exact first.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" { // simple root landing
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("SSO service"))
			return
		}
		log.Printf("404 for path=%s", r.URL.Path)
		http.NotFound(w, r)
	})

	// Wrap with logging middleware to observe route matching during debugging.
	loggedHandler := withRequestLogging(mux)
	// /authorize handler omitted (future step) – will issue authorization codes & handle PKCE.

	addr := ":8080"
	if v := os.Getenv("PORT"); v != "" {
		addr = ":" + v
	}

	srv := &http.Server{Addr: addr, Handler: loggedHandler, ReadHeaderTimeout: 10 * time.Second}

	go func() {
		log.Printf("SSO service starting on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutdown signal received")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "graceful shutdown failed: %v\n", err)
	}
}

// withRequestLogging adds simple structured request logs including status and latency.
func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, sw.status, time.Since(start))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// seedDemo inserts a single demo user & client for quick manual curl testing.
func seedDemo(userRepo interface {
	Create(context.Context, *entity.User) error
	GetByEmail(context.Context, string) (*entity.User, error)
}, clientRepo interface {
	Create(context.Context, *entity.Client) error
}) {
	ctx := context.Background()
	// Using minimal duplication to avoid pulling in external hash libs now.
	u, _ := entity.NewUser("user@example.com", "dummy-hash")
	_ = userRepo.Create(ctx, u)
	c, _ := entity.NewClient("app123", "Demo App", "", []string{"http://localhost:3000/cb"}, []string{"openid", "profile"}, false, true)
	_ = clientRepo.Create(ctx, c)
}
