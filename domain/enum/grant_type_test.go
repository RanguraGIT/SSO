package enum

import "testing"

func TestGrantTypeParse(t *testing.T) {
	gt, err := ParseGrantType("authorization_code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gt != GrantTypeAuthorizationCode {
		t.Fatalf("expected authorization_code got %s", gt)
	}
	if _, err := ParseGrantType("invalid"); err == nil {
		t.Fatal("expected error for invalid grant type")
	}
}
