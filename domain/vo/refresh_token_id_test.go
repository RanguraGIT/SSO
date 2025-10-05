package vo

import "testing"

func TestRefreshTokenID(t *testing.T) {
	_, err := NewRefreshTokenID("")
	if err == nil {
		t.Fatal("expected error for empty id")
	}

	rid, err := NewRefreshTokenID("abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rid.String() != "abc123" {
		t.Fatalf("unexpected value: %s", rid.String())
	}
}
