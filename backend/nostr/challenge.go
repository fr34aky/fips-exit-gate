package nostr

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// Login challenges are stateless: a random nonce plus an expiry, authenticated
// with an HMAC. The portal issues one, the client signs an event carrying it,
// and the server re-verifies the HMAC + expiry — no server-side challenge store.

// ChallengeTTLSeconds is how long an issued challenge is valid.
const ChallengeTTLSeconds = 120

// AuthEventKind is the nostr event kind required for a login (NIP-42 style).
// Requiring a specific kind — plus the challenge in a tag (not free content) —
// prevents an attacker from replaying a victim's ordinary signed note (kind 1)
// whose text happens to contain the challenge.
const AuthEventKind = 27235

// IssueChallenge returns a signed challenge string valid for ChallengeTTLSeconds.
func IssueChallenge(secret []byte, nowUnix int64) string {
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	exp := nowUnix + ChallengeTTLSeconds
	payload := base64.RawURLEncoding.EncodeToString(nonce[:]) + "." + strconv.FormatInt(exp, 10)
	mac := macOf(secret, payload)
	return payload + "." + mac
}

// VerifyChallenge checks a challenge's HMAC and expiry.
func VerifyChallenge(secret []byte, challenge string, nowUnix int64) error {
	parts := strings.Split(challenge, ".")
	if len(parts) != 3 {
		return fmt.Errorf("nostr: malformed challenge")
	}
	if !hmac.Equal([]byte(parts[2]), []byte(macOf(secret, parts[0]+"."+parts[1]))) {
		return fmt.Errorf("nostr: bad challenge signature")
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return fmt.Errorf("nostr: bad challenge expiry")
	}
	if nowUnix > exp {
		return fmt.Errorf("nostr: challenge expired")
	}
	return nil
}

// ExtractChallenge returns the challenge an auth event carries in its
// ["challenge", <value>] tag (NIP-42 style), or "" if absent. It deliberately
// does NOT fall back to the event content — accepting content-as-challenge would
// let a signed ordinary note authenticate.
func ExtractChallenge(e *Event) string {
	for _, t := range e.Tags {
		if len(t) >= 2 && t[0] == "challenge" {
			return t[1]
		}
	}
	return ""
}

// UsedChallenges makes challenges single-use: a successfully verified
// challenge is remembered until it would have expired anyway, and a second
// presentation is refused. In-memory and per-process (challenges are issued
// and verified by the same backend).
type UsedChallenges struct {
	mu   sync.Mutex
	seen map[string]int64 // challenge -> expiry unix
}

// NewUsedChallenges returns an empty cache.
func NewUsedChallenges() *UsedChallenges { return &UsedChallenges{seen: map[string]int64{}} }

// Consume records challenge as used and reports whether it was fresh. Expired
// entries are pruned opportunistically.
func (u *UsedChallenges) Consume(challenge string, nowUnix int64) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if exp, dup := u.seen[challenge]; dup && exp >= nowUnix {
		return false
	}
	if len(u.seen) > 1024 {
		for c, exp := range u.seen {
			if exp < nowUnix {
				delete(u.seen, c)
			}
		}
	}
	u.seen[challenge] = nowUnix + ChallengeTTLSeconds
	return true
}

// ExtractTag returns the first value of the named tag, or "".
func ExtractTag(e *Event, name string) string {
	for _, t := range e.Tags {
		if len(t) >= 2 && t[0] == name {
			return t[1]
		}
	}
	return ""
}

func macOf(secret []byte, msg string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}
