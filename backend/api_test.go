package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fr34aky/fips-exit-gate/pkg/authzhash"
	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
)

const apiTestNpub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"

// A forced reconcile (full=1) on a backend whose revision is still 0 must get
// the (empty) full set back, not a long-poll 204: the agent uses it to clear
// stale kernel entries. Without the flag, rev 0 == cur 0 still long-polls.
func TestAuthzHandlerFullFlagAtRevisionZero(t *testing.T) {
	st := testStoreMain(t)
	h := &handlers{store: st, fallbackPoll: 10 * time.Millisecond}

	rec := httptest.NewRecorder()
	h.authz(rec, httptest.NewRequest("GET", "/v1/nodes/n/authz?rev=0&wait=1&full=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("full=1 at rev 0: status %d, want 200", rec.Code)
	}
	var body struct {
		Rev       int64 `json:"rev"`
		Full      bool  `json:"full"`
		Addresses []any `json:"addresses"`
		Force     bool  `json:"force"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Full || body.Rev != 0 || len(body.Addresses) != 0 || body.Force {
		t.Fatalf("unexpected full body: %+v", body)
	}

	rec = httptest.NewRecorder()
	start := time.Now()
	h.authz(rec, httptest.NewRequest("GET", "/v1/nodes/n/authz?rev=0&wait=1", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("plain rev=0 at rev 0 should long-poll to 204, got %d", rec.Code)
	}
	if time.Since(start) < 900*time.Millisecond {
		t.Fatal("long-poll returned before its wait elapsed")
	}

	h.allowMassRevoke = true
	rec = httptest.NewRecorder()
	h.authz(rec, httptest.NewRequest("GET", "/v1/nodes/n/authz?rev=0&full=1", nil))
	if !strings.Contains(rec.Body.String(), `"force":true`) {
		t.Fatalf("AUTHZ_ALLOW_MASS_REVOKE must mark full responses force=true: %s", rec.Body.String())
	}
}

// A long-poll parked at the current revision must wake on the NOTIFY that
// RecomputeAuthz emits, well before the fallback poll would have fired.
func TestAuthzLongPollWakesOnNotify(t *testing.T) {
	st := testStoreMain(t)
	h := &handlers{store: st, revs: newRevWaiter(), fallbackPoll: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go st.ListenAuthz(ctx, h.revs.broadcast)
	time.Sleep(200 * time.Millisecond) // let LISTEN attach

	cur, err := st.CurrentRev(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/v1/nodes/n/authz?rev="+itoa(cur)+"&wait=20", nil)
		h.authz(rec, req)
		done <- rec
	}()
	time.Sleep(200 * time.Millisecond) // the poll is parked now
	if err := st.CreditTime(ctx, apiTestNpub, 1); err != nil {
		t.Fatal(err)
	}
	select {
	case rec := <-done:
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d, want 200 delta", rec.Code)
		}
		addr, _ := fipsaddr.FromNpub(apiTestNpub)
		if !strings.Contains(rec.Body.String(), addr.String()) {
			t.Fatalf("delta does not carry the new address: %s", rec.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long-poll did not wake on NOTIFY (fallback poll is 1h)")
	}
}

// Drift detection compares the agent's set fingerprint at an equal revision;
// a same-size-different-members set is drift, an unreadable set (-1) is not.
func TestHeartbeatResyncUsesSetHash(t *testing.T) {
	st := testStoreMain(t)
	h := &handlers{store: st}
	ctx := context.Background()
	if err := st.CreditTime(ctx, apiTestNpub, 1); err != nil {
		t.Fatal(err)
	}
	tok, _ := st.CreateEnrollToken(ctx, "n")
	nodeID, _, err := st.EnrollNode(ctx, tok, "pk", "node")
	if err != nil {
		t.Fatal(err)
	}
	_, hash, rev, err := st.AuthzStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hb := func(body string) bool {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/nodes/"+nodeID+"/heartbeat", strings.NewReader(body))
		req.SetPathValue("id", nodeID)
		h.heartbeat(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("heartbeat status %d: %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Resync bool `json:"resync"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Resync
	}
	wrongHash := authzhash.Of(nil)
	if hb(`{"authz_rev":` + itoa(rev) + `,"set_size":1,"set_hash":"` + hash + `"}`) {
		t.Fatal("matching hash flagged as drift")
	}
	if !hb(`{"authz_rev":` + itoa(rev) + `,"set_size":1,"set_hash":"` + wrongHash + `"}`) {
		t.Fatal("same size, different members not flagged as drift")
	}
	if hb(`{"authz_rev":` + itoa(rev-1) + `,"set_size":1,"set_hash":"` + wrongHash + `"}`) {
		t.Fatal("a node that is merely behind must not be resynced")
	}
	if hb(`{"authz_rev":` + itoa(rev) + `,"set_size":-1}`) {
		t.Fatal("unreadable set (-1) flagged as drift")
	}
	if !hb(`{"authz_rev":` + itoa(rev) + `,"set_size":0}`) {
		t.Fatal("legacy size-only mismatch not flagged")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
