package test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/RanguraGIT/sso/domain/entity"
	du "github.com/RanguraGIT/sso/domain/usecase"
	"github.com/RanguraGIT/sso/infrastructure/persistence"
	mysqlrepo "github.com/RanguraGIT/sso/infrastructure/repository/mysql"
	iservice "github.com/RanguraGIT/sso/infrastructure/service"
	"github.com/RanguraGIT/sso/infrastructure/usecase"
)

// TestIssueAndRefreshRotation covers initial issuance and a single refresh ensuring rotation metadata updates.
func TestIssueAndRefreshRotation(t *testing.T) {
	// Setup MySQL test database (requires env vars configured for test DB)
	db := openTestDB(t)
	clients := mysqlrepo.NewClientRepo(db)
	users := mysqlrepo.NewUserRepo(db)
	tokens := mysqlrepo.NewTokenRepo(db)
	// seed client & user
	client, _ := entity.NewClient("test-client", "Test Client", "", []string{"http://localhost/cb"}, []string{"openid", "profile"}, false, true)
	_ = clients.Create(context.Background(), client)
	user, _ := entity.NewUser("user@example.com", "hashpw")
	_ = users.Create(context.Background(), user)

	keys := iservice.NewInMemoryKeyRotation(15 * time.Minute)
	jwtSvc := iservice.NewJWTTokenService(keys)
	issue := usecase.NewIssueToken(clients, tokens, jwtSvc)
	refreshUC := usecase.NewRefreshToken(tokens, clients, jwtSvc)

	out, err := issue.Execute(context.Background(), du.IssueTokenInput{
		UserID: user.ID, ClientID: client.ClientID, Scope: "openid profile", Audience: []string{client.ClientID}, Issuer: "http://issuer", AccessTTL: time.Minute, RefreshTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("issue execute: %v", err)
	}
	if out.IDToken == "" {
		t.Fatalf("expected id token issued")
	}

	// Locate stored token metadata
	// Hash refresh token like handler does to obtain stored identifier
	rot := sha256Sum(out.RefreshToken)
	meta, err := tokens.GetByRefreshID(context.Background(), rot)
	if err != nil || meta == nil {
		t.Fatalf("expected stored token meta; err=%v", err)
	}
	if meta.ParentRefreshID != "" {
		t.Fatalf("initial token should have no parent")
	}

	// Perform refresh
	time.Sleep(1100 * time.Millisecond) // ensure new iat second so JWT differs
	refOut, err := refreshUC.Execute(context.Background(), du.RefreshTokenInput{RefreshTokenID: rot, Issuer: "http://issuer", Audience: []string{client.ClientID}, AccessTTL: time.Minute, RefreshTTL: time.Hour})
	if err != nil {
		t.Fatalf("refresh execute: %v", err)
	}
	if refOut.AccessToken == out.AccessToken {
		t.Fatalf("access token should rotate")
	}

	// New token metadata should exist and parent should link
	newHash := sha256Sum(refOut.RefreshToken)
	newMeta, err := tokens.GetByRefreshID(context.Background(), newHash)
	if err != nil || newMeta == nil {
		t.Fatalf("expected new token meta err=%v", err)
	}
	if newMeta.ParentRefreshID == "" || newMeta.ParentRefreshID != rot {
		t.Fatalf("expected parent link to original hash")
	}
}

func sha256Sum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// openTestDB opens and migrates a MySQL database for testing.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// Allow overriding database name for isolation
	if os.Getenv("DB_NAME") == "" {
		os.Setenv("DB_NAME", "rangura_test")
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
