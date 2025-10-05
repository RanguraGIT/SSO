package vo

import (
	"testing"
)

func TestEmailValidation(t *testing.T) {
	_, err := NewEmail("")
	if err == nil {
		t.Fatal("expected error for empty email")
	}

	e, err := NewEmail("user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.String() != "user@example.com" {
		t.Fatalf("unexpected value: %s", e.String())
	}
}
