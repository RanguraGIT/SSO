package vo

import (
	"testing"
)

func TestPasswordHash(t *testing.T) {
	_, err := NewPasswordHash("")
	if err == nil { t.Fatal("expected error for empty hash") }

	h, err := NewPasswordHash("$argon2id$v=19$m=65536,t=1,p=2$saltsalt$deadbeef")
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if h.String() == "" { t.Fatal("hash string should not be empty") }
}
