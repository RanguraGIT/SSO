package vo

import (
	"testing"
	"time"
)

func TestJWTClaimsExpires(t *testing.T) {
	c := JWTClaims{
		Subject:   "user-1",
		Audience:  []string{"client-1"},
		Issuer:    "https://issuer.example.com",
		IssuedAt:  time.Now().Add(-1 * time.Minute).Unix(),
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	if c.IsExpired(time.Now()) {
		// should not be expired
		t.Fatal("claims should not be expired")
	}
	c.ExpiresAt = time.Now().Add(-1 * time.Minute).Unix()
	if !c.IsExpired(time.Now()) {
		t.Fatal("claims should be expired")
	}
}
