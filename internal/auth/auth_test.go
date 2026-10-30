package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected PHC prefix: %s", h)
	}
	if ok, err := VerifyPassword("correct horse battery staple", h); err != nil || !ok {
		t.Fatalf("valid password rejected: %v", err)
	}
	if ok, _ := VerifyPassword("wrong", h); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("salt not random")
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	for _, h := range []string{
		"",
		"$argon2i$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA",
		"$argon2id$v=18$m=65536,t=3,p=2$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=0,t=3,p=2$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!$aGFzaA",
	} {
		if _, err := VerifyPassword("x", h); err == nil {
			t.Errorf("VerifyPassword accepted %q", h)
		}
	}
}

func TestAllowed(t *testing.T) {
	tests := []struct {
		have, need string
		want       bool
	}{
		{RoleAdmin, RoleViewer, true},
		{RoleAnalyst, RoleAnalyst, true},
		{RoleViewer, RoleAnalyst, false},
		{RoleAnalyst, RoleAdmin, false},
		{"", RoleViewer, false},
		{RoleAdmin, "root", false},
	}
	for _, tt := range tests {
		if got := Allowed(tt.have, tt.need); got != tt.want {
			t.Errorf("Allowed(%q, %q) = %v", tt.have, tt.need, got)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(time.Hour, 3)
	for i := range 3 {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("attempt %d rejected", i)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("burst exceeded but allowed")
	}
	if !l.Allow("5.6.7.8") {
		t.Fatal("keys are not independent")
	}
}

func TestToken(t *testing.T) {
	a, sa, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := NewToken()
	if a == b || len(a) != 43 || len(sa) != 32 {
		t.Fatalf("token %q (%d), hash len %d", a, len(a), len(sa))
	}
	if string(HashToken(a)) != string(sa) {
		t.Fatal("HashToken mismatch")
	}
}
