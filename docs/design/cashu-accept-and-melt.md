# Design note — Cashu payment rail (accept-and-melt)

> **Status: proposal, not implemented.** Design captured 2026-08-10 for a later
> build. Nothing in the codebase implements this yet.

## Why

Add Cashu (Chaumian ecash) as an optional payment method. Two variants were
scoped; this note covers the **cheaper, no-custody** one. The other is recorded
under "Alternative" below.

## Key insight

An **accept-and-melt** Cashu payment lands as a Lightning payment **into the
existing phoenixd node**, so it rides the settlement path we already built. The
mint pays the purchase's invoice instead of the buyer's wallet; everything
downstream (`GrantByInvoice`, the phoenixd webhook, the reconciler) is untouched.

Cashu here is **not a new `payments.Provider`** — it's an alternate *funding
method* on the phoenixd rail's `/pay/{id}` page. `Provider.CreateInvoice` is
unchanged. Requires `PAYMENT_RAIL=phoenixd` (a bolt11 must already be attached to
the purchase to melt into).

## Flow

`buy()` already does, for phoenixd: `CreateInvoice` → `AttachInvoice(id, hash,
…/pay/id, bolt11)` → redirect `/pay/{id}`. So a phoenixd bolt11 is already
attached by the time the pay page renders. The Cashu path just gets it paid:

1. Pay page shows the BOLT11 *and* (when `CASHU_ACCEPT=1`) a "paste a Cashu token" box.
2. `POST /pay/{id}/cashu` with `token=cashuB…`.
3. Handler loads the purchase's attached bolt11 (`PurchaseForPay` already returns `Bolt11`).
4. Redeemer asks the **token's own mint** for a melt quote for that exact bolt11
   (NUT-05) → `{amount, fee_reserve}`; checks the token covers `amount +
   fee_reserve`; executes the melt with the proofs.
5. Mint pays our phoenixd invoice → `payment_received` webhook (or reconciler's
   `LookupIncoming`) → `GrantByInvoice(hash)`.
6. The pay page's existing `/pay/{id}/status` poll sees `settled` → redirect to
   dashboard. **Zero new settlement code.**

## Reused vs new

| Reused unchanged | New |
|---|---|
| `payments.Provider` / `CreateInvoice` (phoenixd) | `backend/payments/cashu.go` — `CashuRedeemer` (wraps **gonuts**, `github.com/elnosh/gonuts`) |
| `AttachInvoice`, `GrantByInvoice`, `VoidByInvoice` | `POST /pay/{id}/cashu` handler in `portal.go` |
| `reconciler.go` (webhook + poll settle/expire) | Token textarea in `pay.html` (shown when Cashu enabled) |
| `PurchaseForPay` (already returns `Bolt11`, `Status`) | Config `CASHU_ACCEPT`, `CASHU_ACCEPTED_MINTS` |
| `/pay/{id}/status` poll + `pay.html` JS | (optional) `cashu_melts` audit/idempotency row + migration `0004` |

## Code surface

```go
// backend/payments/cashu.go
type CashuRedeemer struct {
    accepted map[string]bool // optional mint allowlist; empty = accept any
    // gonuts wallet + httpClient (Tor-capable via the existing torHTTPClient helper)
}

// Melt pays `bolt11` using a received Cashu token, via the token's own mint
// (NUT-05: quote -> verify token covers amount+fee_reserve -> melt). Returns the
// sats that will land, or an error if the token is invalid, from a non-accepted
// mint, or underfunded. The mint marks the proofs spent atomically.
func (c *CashuRedeemer) Melt(ctx context.Context, token, bolt11 string) (sat int64, err error)
```

```go
// backend/portal.go — POST /pay/{id}/cashu  (body: token=cashuB...)
func (p *portal) payCashu(w http.ResponseWriter, r *http.Request) {
    npub, _ := p.session(r)
    id := r.PathValue("id")
    pv, _ := p.store.PurchaseForPay(r.Context(), id, npub) // has Bolt11 + Status
    if pv.Status == "settled" { w.WriteHeader(200); return } // idempotent
    if _, err := p.cashu.Melt(r.Context(), r.FormValue("token"), pv.Bolt11); err != nil {
        http.Error(w, "token rejected", http.StatusBadRequest); return
    }
    // mint now pays pv.Bolt11 -> phoenixd receipt -> existing webhook/reconciler grants.
    w.WriteHeader(http.StatusAccepted) // pay page keeps polling /pay/{id}/status
}
```

## Why this is trust-minimized

**Grant only on realized Lightning receipt into our own node.** The external
mint's solvency exposure is bounded to the melt: either it pays our invoice (we
got the value, we grant) or it doesn't (no grant, no loss, and the buyer's token
isn't spent — the mint burns proofs atomically only on a successful melt).

- `CASHU_ACCEPTED_MINTS` is **optional** — a UX/known-good filter, not a security
  control. A malicious mint just yields a failed payment.
- **Not a custodian.** We never hold ecash or issue tokens.
- Idempotency: double-grant already prevented by `GrantByInvoice` (keyed on the
  phoenixd hash); double-spend prevented by the mint. `cashu_melts` with
  `unique(secrets_hash)` is defense-in-depth against concurrent double-submit;
  nothing depends on it for correctness.

## Effort & v1 cuts

~**3–4 focused days**: redeemer via gonuts (~1–1.5d), portal handler + pay.html
box (~0.5–1d), config + optional migration (~0.5d), a `cmd/fake-cashu-mint` test
double mirroring `cmd/fake-phoenixd` + tests (~1d), docs (~0.5d).

v1 cuts:
- **Change handling** — require the token to cover `amount + fee_reserve`;
  overpayment is eaten (or display the mint's change token). Full change-proof
  reconstruction later.
- **BTCPay underneath** — v1 requires `PAYMENT_RAIL=phoenixd`. Supporting melt
  into BTCPay's LN is possible later.
- **Offline pre-funding is NOT delivered by this variant** (see below).

## Alternative — self-hosted mint (separate, bigger project)

Run our own audited mint (`cdk-mintd`, which supports a **phoenixd** backend, or
Nutshell). Buyers mint our ecash by paying Lightning, then spend our tokens for
access. This is the only variant that delivers **offline pre-funding** (buyers
pre-hold value and spend later at intermittent connectivity).

- Effort ~**4–7 days** of code + **you become a custodian** (mint holds the
  backing; users trust it not to rug / to honor melts) — regulatory + trust
  weight the accept-and-melt variant avoids entirely.
- **Hard rule: run an existing audited mint; never implement minting/blind
  signatures ourselves.** Our side would still only implement the receiver.

## Open questions to resolve before building

- Confirm gonuts' current melt-quote/melt API (`Melt` signature above is our
  wrapper, not gonuts verbatim).
- Amount→sats: package `PriceMsat` → the melt quote is for our bolt11 (already
  priced), so this mostly falls out; confirm fee_reserve handling and the
  "insufficient" UX.
- Whether to require `CASHU_ACCEPTED_MINTS` non-empty in production (UX/ops
  choice, not security).
- Decide explicitly which variant (or both, phased) we want: accept-and-melt
  first (no custody, no offline) vs. self-mint (custody, offline).
