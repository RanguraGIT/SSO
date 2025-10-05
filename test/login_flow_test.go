package test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	h "github.com/RanguraGIT/sso/delivery/http/handler"
	"github.com/RanguraGIT/sso/infrastructure/persistence"
	mysqlrepo "github.com/RanguraGIT/sso/infrastructure/repository/mysql"
	iservice "github.com/RanguraGIT/sso/infrastructure/service"
	"github.com/RanguraGIT/sso/infrastructure/usecase"
)

// TestLoginFlow ensures that a POST /login with valid credentials creates a session cookie.
func TestLoginFlow(t *testing.T) {
	// Setup DB and repos
	db, err := persistence.OpenMySQLCreatingDB()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	ctx := context.Background()
	if err := persistence.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	userRepo := mysqlrepo.NewUserRepo(db)
	sessionRepo := mysqlrepo.NewSessionRepo(db)
	// Seed user via register use case to ensure hash + validation (unique email per run)
	bcryptAuth := iservice.NewBcryptAuthService(userRepo, 10).(interface{ HashPassword(string) (string, error) })
	registerUC := usecase.NewRegisterUser(userRepo, bcryptAuth)
	email := "login-user-" + time.Now().UTC().Format("20060102150405.000") + "@example.com"
	if _, err := registerUC.Execute(ctx, usecase.RegisterUserInput{Email: email, Password: "secretpass"}); err != nil {
		t.Fatalf("register user: %v", err)
	}

	loginUC := usecase.NewUserLogin(userRepo, iservice.NewBcryptAuthService(userRepo, 10))
	createSessionUC := usecase.NewCreateSession(sessionRepo)
	handler := &h.LoginHandler{LoginUC: loginUC, SessionUC: createSessionUC}

	body, _ := json.Marshal(map[string]string{"email": email, "password": "secretpass"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 got %d body=%s", w.Code, w.Body.String())
	}
	// Check cookie
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "sid" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("session cookie not set")
	}
	// Basic JSON structure
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["session_id"] == "" {
		t.Fatalf("missing session_id in response")
	}
	// Ensure expiry ~ 8h
	for _, c := range cookies {
		if c.Name == "sid" {
			if c.Expires.Before(time.Now().Add(7 * time.Hour)) {
				t.Fatalf("cookie expiry too short: %v", c.Expires)
			}
		}
	}
}
