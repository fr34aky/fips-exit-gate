package store

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
)

// Extra deterministic npubs for the guest-cap test (distinct names from other
// test files so independent branches merge cleanly).
var (
	npubG = consentTestNpub(0x31)
	npubH = consentTestNpub(0x32)
)

func consentTestNpub(b byte) string {
	var seed [32]byte
	for i := range seed {
		seed[i] = b
	}
	_, pub := btcec.PrivKeyFromBytes(seed[:])
	var x [32]byte
	copy(x[:], pub.SerializeCompressed()[1:33])
	return fipsaddr.EncodeNpub(x)
}

func creditedAccount(t *testing.T, st *Store, npub string) {
	t.Helper()
	if err := st.CreditVolume(context.Background(), npub, 1_000_000, 30); err != nil {
		t.Fatal(err)
	}
}

// The hijack this model prevents: before, anyone could add a victim's npub as
// a guest; the victim's own owner row was then created disabled and a package
// they paid for never authorized them. A pending invitation must not do that.
func TestPendingInviteCannotHijackAnOwner(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	attacker, victim := npubA, npubB
	creditedAccount(t, st, attacker)
	if err := st.InviteGuest(ctx, attacker, victim, "mark"); err != nil {
		t.Fatal(err)
	}
	// Pending: the victim's address is NOT authorized through the attacker.
	if setContains(mustFullSet(t, st), addrOf(t, victim)) {
		t.Fatal("pending invitation authorized the victim's address")
	}
	// Victim shows up, pays: their owner row is active and they are authorized
	// under THEIR account, attacker's row notwithstanding.
	creditedAccount(t, st, victim)
	full := mustFullSet(t, st)
	vAcct, _ := st.GetAccountByNpub(ctx, victim)
	found := false
	for _, m := range full {
		if m.Addr == addrOf(t, victim) {
			found = true
			if m.Account != vAcct.ID {
				t.Fatalf("victim attributed to account %s, want own %s", m.Account, vAcct.ID)
			}
		}
	}
	if !found {
		t.Fatal("victim not authorized after paying for their own package")
	}
	// Transparent login resolves the address to the victim, not via the attacker.
	if np, err := st.NpubByAddr(ctx, addrOf(t, victim)); err != nil || np != victim {
		t.Fatalf("NpubByAddr = %q, %v; want victim", np, err)
	}
}

func TestInviteAcceptDeclineAndSwitchBack(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host, guest := npubA, npubB
	creditedAccount(t, st, host)
	hostAcct, _ := st.GetAccountByNpub(ctx, host)

	if err := st.InviteGuest(ctx, host, guest, "friend"); err != nil {
		t.Fatal(err)
	}
	inv, err := st.PendingInvites(ctx, guest)
	if err != nil || len(inv) != 1 || inv[0].HostNpub != host || inv[0].Label != "friend" {
		t.Fatalf("pending invites = %+v, %v", inv, err)
	}
	if setContains(mustFullSet(t, st), addrOf(t, guest)) {
		t.Fatal("guest authorized before accepting")
	}

	// Guest has (or creates) their own account first, then accepts.
	if _, err := st.CreateAccount(ctx, guest); err != nil {
		t.Fatal(err)
	}
	if err := st.AcceptInvite(ctx, guest, host); err != nil {
		t.Fatal(err)
	}
	full := mustFullSet(t, st)
	attributed := ""
	for _, m := range full {
		if m.Addr == addrOf(t, guest) {
			attributed = m.Account
		}
	}
	if attributed != hostAcct.ID {
		t.Fatalf("after accept, guest attributed to %q, want host %s", attributed, hostAcct.ID)
	}
	guestAcct, _ := st.GetAccountByNpub(ctx, guest)
	if at, _ := st.AttachedTo(ctx, guestAcct.ID, guestAcct.FipsAddr); at != host {
		t.Fatalf("AttachedTo = %q, want host", at)
	}
	if inv, _ := st.PendingInvites(ctx, guest); len(inv) != 0 {
		t.Fatal("accepted invite still pending")
	}
	if err := st.AcceptInvite(ctx, guest, host); err != ErrInviteNotFound {
		t.Fatalf("second accept: %v, want ErrInviteNotFound", err)
	}

	// Guest buys their own package: the address comes home automatically.
	creditedAccount(t, st, guest)
	full = mustFullSet(t, st)
	for _, m := range full {
		if m.Addr == addrOf(t, guest) && m.Account != guestAcct.ID {
			t.Fatalf("after own purchase, guest still attributed to %s", m.Account)
		}
	}
	if at, _ := st.AttachedTo(ctx, guestAcct.ID, guestAcct.FipsAddr); at != "" {
		t.Fatalf("AttachedTo after switching back = %q, want empty", at)
	}
	sum, _ := st.Summary(ctx, host)
	for _, w := range sum.Whitelist {
		if w.Npub == guest && w.Enabled {
			t.Fatal("host's guest row still enabled after the guest switched back")
		}
	}

	// Re-inviting after the guest moved back needs consent again: the row is
	// pending, the guest stays on their own account, and declining removes it.
	if err := st.InviteGuest(ctx, host, guest, "again"); err != nil {
		t.Fatal(err)
	}
	if inv, _ := st.PendingInvites(ctx, guest); len(inv) != 1 {
		t.Fatalf("re-invite should be pending again, got %+v", inv)
	}
	for _, m := range mustFullSet(t, st) {
		if m.Addr == addrOf(t, guest) && m.Account != guestAcct.ID {
			t.Fatalf("re-invite moved the guest without consent (attributed to %s)", m.Account)
		}
	}
	if err := st.DeclineInvite(ctx, guest, host); err != nil {
		t.Fatal(err)
	}
	if inv, _ := st.PendingInvites(ctx, guest); len(inv) != 0 {
		t.Fatal("declined invitation still pending")
	}
	if err := st.DeclineInvite(ctx, guest, host); err != ErrInviteNotFound {
		t.Fatalf("second decline: %v, want ErrInviteNotFound", err)
	}

	// Owner-side toggle: re-enabling a disabled guest whose address is active
	// elsewhere becomes pending rather than violating the one-active-row rule.
	if err := st.AddWhitelist(ctx, host, guest, "admin"); err != ErrAddressInUse {
		t.Fatalf("admin add while active elsewhere: %v, want ErrAddressInUse", err)
	}
	if err := st.InviteGuest(ctx, host, guest, "x"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetWhitelistEnabled(ctx, host, guest, false); err != nil {
		t.Fatal(err)
	}
	if err := st.SetWhitelistEnabled(ctx, host, guest, true); err != nil {
		t.Fatalf("re-enable while active elsewhere must not fail: %v", err)
	}
	if inv, _ := st.PendingInvites(ctx, guest); len(inv) != 1 {
		t.Fatal("re-enabled guest row should be pending (consent needed)")
	}
}

func TestInviteGuards(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := npubA
	if _, err := st.CreateAccount(ctx, host); err != nil {
		t.Fatal(err)
	}
	if err := st.InviteGuest(ctx, host, npubB, ""); err != ErrNoActiveEntitlement {
		t.Fatalf("invite without a package: %v, want ErrNoActiveEntitlement", err)
	}
	creditedAccount(t, st, host)
	if err := st.InviteGuest(ctx, host, host, ""); err != ErrSelfWhitelist {
		t.Fatalf("self invite: %v, want ErrSelfWhitelist", err)
	}
	st.MaxGuests = 2
	if err := st.InviteGuest(ctx, host, npubB, "1"); err != nil {
		t.Fatal(err)
	}
	if err := st.InviteGuest(ctx, host, npubG, "2"); err != nil {
		t.Fatal(err)
	}
	if err := st.InviteGuest(ctx, host, npubH, "3"); err != ErrGuestLimit {
		t.Fatalf("third guest with cap 2: %v, want ErrGuestLimit", err)
	}
	// Re-inviting an existing guest does not count against the cap.
	if err := st.InviteGuest(ctx, host, npubB, "relabel"); err != nil {
		t.Fatalf("re-invite existing guest: %v", err)
	}
	// Admin path stays immediate and uncapped (operator support).
	if err := st.AddWhitelist(ctx, host, npubH, "admin-added"); err != nil {
		t.Fatal(err)
	}
	if !setContains(mustFullSet(t, st), addrOf(t, npubH)) {
		t.Fatal("admin-added guest not authorized immediately")
	}
}

func TestInspectShowsConflicts(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host, guest := npubA, npubB
	creditedAccount(t, st, host)
	if err := st.InviteGuest(ctx, host, guest, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAccount(ctx, guest); err != nil {
		t.Fatal(err)
	}
	insp, err := st.Inspect(ctx, guest)
	if err != nil {
		t.Fatal(err)
	}
	if len(insp.Invites) != 1 || insp.Invites[0].HostNpub != host {
		t.Fatalf("inspect invites = %+v", insp.Invites)
	}
	var owner *InspectedEntry
	for i := range insp.Whitelist {
		if insp.Whitelist[i].Role == "owner" {
			owner = &insp.Whitelist[i]
		}
	}
	if owner == nil || len(owner.Conflicts) != 1 || owner.Conflicts[0].AccountNpub != host || !owner.Conflicts[0].Pending {
		t.Fatalf("owner row conflicts = %+v", owner)
	}
	if owner.Authorized {
		t.Fatal("guest without a package reported as authorized")
	}
	hostInsp, _ := st.Inspect(ctx, host)
	for _, e := range hostInsp.Whitelist {
		if e.Role == "owner" && (!e.Authorized || e.AuthzOwner != host) {
			t.Fatalf("host owner row authz state wrong: %+v", e)
		}
	}
}
