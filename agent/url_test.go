package main

import "testing"

func TestCheckBackendURL(t *testing.T) {
	ok := []string{
		"https://backend.example:8080",
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://[::1]:8080",
		"http://[fd00:1234::1]:8080", // a fips address: encrypted by the mesh
		"http://npub1abc.fips:8080",  // a .fips name
	}
	for _, u := range ok {
		if err := checkBackendURL(u, false); err != nil {
			t.Errorf("%s: unexpected error: %v", u, err)
		}
	}
	bad := []string{
		"http://backend.example:8080", // plain http across the Internet
		"http://203.0.113.5:8080",
		"ftp://x",
		"backend.example",
	}
	for _, u := range bad {
		if err := checkBackendURL(u, false); err == nil {
			t.Errorf("%s: accepted without FIPS_AGENT_ALLOW_INSECURE", u)
		}
	}
	if err := checkBackendURL("http://backend.example:8080", true); err != nil {
		t.Errorf("override not honoured: %v", err)
	}
	if err := checkBackendURL("ftp://x", true); err == nil {
		t.Error("bad scheme accepted even with override")
	}
}
