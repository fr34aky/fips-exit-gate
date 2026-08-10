# Phase 4 — Payments (BTCPay + Monero over Tor)

The fips-exit portal charges for data packages with a self-hosted **BTCPay
Server**, wired to your **external** bitcoind (and monerod, via the Monero
plugin) reachable over **Tor**. A purchase creates a BTCPay invoice; BTCPay's
signed webhook drives the purchase lifecycle in the backend.

```
buyer ──/buy──▶ backend ──Greenfield──▶ BTCPay ──▶ external bitcoind/monerod (Tor)
   ▲                                        │
   └────────── checkout redirect ◀──────────┘
backend ◀──── signed webhook (BTCPay-Sig HMAC) ──── BTCPay
```

## Design decisions (settled)

- **One sats price per package.** Invoices are denominated in **BTC** for the
  package's sats price (`btcAmount` in `backend/payments/btcpay.go`). BTCPay
  offers BTC on-chain, Lightning, and Monero as payment methods and converts the
  XMR amount with its configured rate provider — no per-rail pricing to maintain.
- **Grant only on settlement (payment finalized).** Access is granted on
  `InvoiceSettled` — i.e. after the payment is final per the store's confirmation
  policy: **≥ 1 block for on-chain Bitcoin**, immediate for Lightning (no
  confirmations exist), and the plugin's confirmations for Monero.
  `InvoiceProcessing` (payment *seen* — e.g. an on-chain tx still at 0-conf in the
  mempool) only updates the purchase to a "confirming…" status; it grants **no**
  access. This avoids unlocking on a reversible 0-conf transaction that could be
  double-spent or dropped (and then revoked ~an hour later when the invoice goes
  invalid). Lightning users still unlock instantly because LN invoices settle
  immediately.
- **The webhook is the only crediting path.** `store.GrantByInvoice` /
  `store.VoidByInvoice` are idempotent and safe against replayed / out-of-order
  deliveries; an already-`settled` purchase is never downgraded or voided.

## Webhook → store mapping

| BTCPay event        | Backend action              | Purchase status | Grants access? |
|---------------------|-----------------------------|-----------------|----------------|
| `InvoiceProcessing` | `MarkProcessing`            | `processing`    | **no** (seen, not final) |
| `InvoiceSettled`    | `GrantByInvoice`            | `settled`       | **yes** (final) |
| `InvoiceExpired`    | `VoidByInvoice("expired")`  | `expired`       | no (revokes if any) |
| `InvoiceInvalid`    | `VoidByInvoice("invalid")`  | `invalid`       | no (revokes if any) |

Other events are acked (2xx) and ignored. Unknown invoices are also acked so
BTCPay stops retrying.

### On-chain finalization (required BTCPay store setting)

Because access is granted on `InvoiceSettled`, the confirmation threshold is
whatever makes BTCPay fire that event — the store's **Transaction Speed** /
invoice-confirmation setting. Configure it so on-chain requires **at least one
confirmation**:

> Store → Settings → **General / Invoice** → **Transaction Speed** →
> **`Medium` (1 confirmation)** — or slower (`Low Medium` = 2, `Low` = 6) for
> larger amounts.

Do **not** use `High` (0-confirmation): that would settle on-chain invoices at
0-conf, defeating the finalization guarantee. Lightning is unaffected (final on
receipt); Monero settles per the Monero plugin's confirmation setting.

## Backend configuration

Set in `deploy/backend.env` (see `backend.env.example`):

```sh
BTCPAY_URL=http://<btcpay-onion>.onion     # or https://btcpay.example
BTCPAY_API_KEY=<store Greenfield API key>  # permission: btcpay.store.cancreateinvoice
BTCPAY_STORE_ID=<store id>
BTCPAY_WEBHOOK_SECRET=<store webhook secret>
BTCPAY_SOCKS5=tor:9050                      # to reach a .onion; empty for clearnet https
PORTAL_PUBLIC_URL=https://portal.example    # buyer is redirected here post-pay
```

Leaving `BTCPAY_URL` empty disables payments (purchases stay `pending`). For
local development without any rail, set `PORTAL_DEV_AUTOSETTLE=1` to grant
immediately.

## Standing up BTCPay against external nodes over Tor

`deploy/btcpay-compose.yaml` runs a lean stack (Tor + NBXplorer + BTCPay +
Postgres). For production, the officially supported deployment is
[btcpayserver-docker](https://github.com/btcpayserver/btcpayserver-docker); the
wiring below applies to either.

1. **External Bitcoin node.** Point NBXplorer at your bitcoind's RPC and P2P
   onions through Tor (`BTC_RPC_URL`, `BTC_P2P_ENDPOINT`, `BTC_RPC_USER/PASSWORD`
   in a `btcpay.env`). NBXplorer dials them via `NBXPLORER_SOCKSENDPOINT=tor:9050`.
   Keep the node fully external — BTCPay only needs RPC/P2P access.

2. **Lightning.** BTCPay supports LND or CLN; pick one at setup (deferred
   decision — the Greenfield invoice flow is identical either way). Connect it to
   your external node.

3. **Monero.** Install the **Monero community plugin** in BTCPay
   (Server Settings → Plugins), then add a Monero wallet using a **view-only**
   wallet on the server pointed at your external monerod over Tor. Enable XMR as
   a payment method on the store.

4. **Tor hidden service.** After first start, read the onion from
   `deploy/` Tor volume at `hidden_services/btcpay/hostname`, set it as
   `BTCPAY_HOST` (btcpay-compose) and `BTCPAY_URL=http://<onion>` (backend.env).

5. **Store + API key.** Create the store, then a Greenfield API key with the
   `btcpay.store.cancreateinvoice` permission → `BTCPAY_API_KEY` / `BTCPAY_STORE_ID`.

6. **Webhook.** Add a store webhook to
   `${PORTAL_PUBLIC_URL}/payments/btcpay/webhook`, subscribed to the invoice
   events above, with automatic redelivery on. Copy its secret to
   `BTCPAY_WEBHOOK_SECRET`.

## Local smoke test with `cmd/fake-btcpay`

Exercise the full HMAC-signed flow with no BTCPay server — the recipe (grant only
on `InvoiceSettled`, headless `/sim` calls) lives in
[Testing payments](testing-payments.md#btcpay-cmdfake-btcpay).

## Threat model note

Access is granted only on `InvoiceSettled`, so an on-chain payment that is seen
but later reorged away or dropped never grants access — the buyer stays in
"confirming…" until the payment reaches the store's confirmation threshold
(≥ 1 block; see *On-chain finalization* above). Lightning is final on receipt and
unaffected. The residual risk is a **reorg deeper than the configured
confirmation count**; raise Transaction Speed (2–6 confirmations) for
higher-value packages if that matters for your threat model.
