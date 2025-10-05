package enum

import "testing"

func TestTokenType(t *testing.T) {
	if AccessToken.String() != "access_token" {
		t.Fatalf("unexpected: %s", AccessToken)
	}
	if RefreshToken.String() != "refresh_token" {
		t.Fatalf("unexpected: %s", RefreshToken)
	}
}
