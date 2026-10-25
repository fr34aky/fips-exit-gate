package version

import "testing"

func TestStringPrefersLinkedVersion(t *testing.T) {
	defer func(v string) { Version = v }(Version)
	Version = "v0.3.1"
	if got := String(); got != "0.3.1" {
		t.Fatalf("String() = %q, want 0.3.1 (leading v stripped)", got)
	}
	Version = "0.3.1-2-gabcdef0-dirty"
	if got := String(); got != "0.3.1-2-gabcdef0-dirty" {
		t.Fatalf("String() = %q", got)
	}
	Version = ""
	if got := String(); got == "" {
		t.Fatal("String() must never be empty")
	}
}
