package test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/RanguraGIT/sso/domain/entity"
	h "github.com/RanguraGIT/sso/infrastructure/delivery/http/handler"
	"github.com/RanguraGIT/sso/infrastructure/persistence"
	mysqlrepo "github.com/RanguraGIT/sso/infrastructure/repository/mysql"
	iservice "github.com/RanguraGIT/sso/infrastructure/service"
	"github.com/RanguraGIT/sso/infrastructure/usecase"
)

// TestEndToEndAuthorizationCodeFlow covers: register (seed), login (session), authorize -> code, token exchange -> id_token, refresh -> new pair, reuse detection.
func TestEndToEndAuthorizationCodeFlow(t *testing.T) {
	// Setup DB
	db := openIntegrationDB(t)
	clientRepo := mysqlrepo.NewClientRepo(db)
	userRepo := mysqlrepo.NewUserRepo(db)
	tokenRepo := mysqlrepo.NewTokenRepo(db)
	codeRepo := mysqlrepo.NewAuthCodeRepo(db)
	sessionRepo := mysqlrepo.NewSessionRepo(db)

	// Seed user + client
	user, _ := entity.NewUser("alice@example.com", "pwd-hash")
	_ = userRepo.Create(context.Background(), user)
	client, _ := entity.NewClient("cli123", "Test SPA", "", []string{"http://localhost/cb"}, []string{"openid", "profile"}, false, true)
	_ = clientRepo.Create(context.Background(), client)

	keys := iservice.NewInMemoryKeyRotation(1 * time.Hour)
	tokenSvc := iservice.NewJWTTokenService(keys)
	issueUC := usecase.NewIssueToken(clientRepo, tokenRepo, tokenSvc)
	startAuthUC := usecase.NewStartAuthorization(clientRepo, codeRepo)
	refreshUC := usecase.NewRefreshToken(tokenRepo, clientRepo, tokenSvc)

	authHandler := &h.AuthorizeHandler{Start: startAuthUC, Sessions: sessionRepo}
	tokenHandler := &h.TokenHandler{Issue: issueUC, Refresh: refreshUC, Codes: codeRepo}

	// Create session for user to simulate login
	sess, _ := entity.NewSession(user.ID, time.Hour, "127.0.0.1", "test-agent")
	_ = sessionRepo.Create(context.Background(), sess)

	// 1. /authorize
	req := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id="+url.QueryEscape(client.ClientID)+"&redirect_uri="+url.QueryEscape(client.RedirectURIs[0])+"&scope=openid+profile&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sess.ID.String()})
	w := httptest.NewRecorder()
	authHandler.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("authorize expected 200 got %d body=%s", w.Code, w.Body.String())
	}
	var authResp struct{ Code, State string }
	_ = json.Unmarshal(w.Body.Bytes(), &authResp)
	if authResp.Code == "" || authResp.State != "xyz" {
		t.Fatalf("bad authorize response: %+v", authResp)
	}

	// 2. /token exchange
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", authResp.Code)
	form.Set("client_id", client.ClientID)
	form.Set("redirect_uri", client.RedirectURIs[0])
	req2 := httptest.NewRequest(http.MethodPost, "/token", io.NopCloser(strings.NewReader(form.Encode())))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	tokenHandler.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("token exchange failed code=%d body=%s", w2.Code, w2.Body.String())
	}
	var tokResp map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &tokResp)
	access1, _ := tokResp["access_token"].(string)
	refresh1, _ := tokResp["refresh_token"].(string)
	if access1 == "" || refresh1 == "" || tokResp["id_token"].(string) == "" {
		t.Fatalf("missing tokens in response: %v", tokResp)
	}

	// 3. /token refresh
	time.Sleep(1100 * time.Millisecond)
	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", refresh1)
	form2.Set("client_id", client.ClientID)
	req3 := httptest.NewRequest(http.MethodPost, "/token", io.NopCloser(strings.NewReader(form2.Encode())))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w3 := httptest.NewRecorder()
	tokenHandler.ServeHTTP(w3, req3)
	if w3.Code != 200 {
		t.Fatalf("refresh failed code=%d body=%s", w3.Code, w3.Body.String())
	}
	var refResp map[string]any
	_ = json.Unmarshal(w3.Body.Bytes(), &refResp)
	access2, _ := refResp["access_token"].(string)
	refresh2, _ := refResp["refresh_token"].(string)
	if access2 == access1 {
		t.Fatalf("expected rotated access token")
	}
	if refresh2 == refresh1 {
		t.Fatalf("expected rotated refresh token")
	}
	if _, has := refResp["id_token"]; has {
		t.Fatalf("refresh response must not include id_token")
	}

	// 4. Reuse detection (old refresh again)
	form3 := url.Values{}
	form3.Set("grant_type", "refresh_token")
	form3.Set("refresh_token", refresh1) // old one
	form3.Set("client_id", client.ClientID)
	req4 := httptest.NewRequest(http.MethodPost, "/token", io.NopCloser(strings.NewReader(form3.Encode())))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w4 := httptest.NewRecorder()
	tokenHandler.ServeHTTP(w4, req4)
	if w4.Code == 200 {
		t.Fatalf("expected failure on refresh reuse, got 200")
	}
}

// (Custom reader helpers removed; using standard library io.NopCloser + strings.NewReader.)

// openIntegrationDB prepares a MySQL database for integration testing.
func openIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv("DB_NAME") == "" {
		os.Setenv("DB_NAME", "rangura_integration")
	}
	db, err := persistence.OpenMySQLCreatingDB()
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := persistence.Migrate(ctx, db); err != nil {
		_ = db.Close()
		t.Fatalf("migrate: %v", err)
	}
	return db
}
