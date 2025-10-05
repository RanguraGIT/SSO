package enum

import "testing"

func TestScopeSet(t *testing.T) {
	set := ParseScopeString("openid profile email")
	if !set.Has("openid") || !set.Has("profile") || !set.Has("email") {
		t.Fatal("expected scopes present")
	}
	if set.Has("missing") {
		t.Fatal("did not expect missing scope")
	}
	if set.String() != "email openid profile" {
		t.Fatalf("normalized ordering unexpected: %s", set.String())
	}
}
