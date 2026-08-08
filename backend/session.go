package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookie   = "fips_session"
	sessionTTLHours = 24 * 7
)

// Sessions are stateless signed cookies: base64url(npub).exp.mac. No server
// store; the HMAC secret authenticates them.

func (p *portal) setSession(w http.ResponseWriter, npub string) {
	exp := time.Now().Add(sessionTTLHours * time.Hour).Unix()
	b := base64.RawURLEncoding.EncodeToString([]byte(npub))
	payload := b + "." + strconv.FormatInt(exp, 10)
	value := payload + "." + sessionMAC(p.sessionSecret, payload)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   p.secureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(exp, 0),
	})
}

func (p *portal) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: p.secureCookies, SameSite: http.SameSiteLaxMode,
	})
}

// session returns the logged-in npub, if the cookie is present and valid.
func (p *portal) session(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return "", false
	}
	if !hmac.Equal([]byte(parts[2]), []byte(sessionMAC(p.sessionSecret, parts[0]+"."+parts[1]))) {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	npub, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	return string(npub), true
}

func sessionMAC(secret []byte, msg string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}
