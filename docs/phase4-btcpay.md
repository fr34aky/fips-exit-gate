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
- **Optimistic unlock.** Access is granted when a payment is *seen*
  (`InvoiceProcessing`), before full confirmation, then confirmed on
  `InvoiceSettled`. If the invoice later goes `InvoiceInvalid`/`InvoiceExpired`
  the entitlement is revoked. This trades a small reorg window for a snappy UX
  (an explicit choice — see the threat model note below).
- **The webhook is the only crediting path.** `store.GrantByInvoice` /
  `store.VoidByInvoice` are idempotent and safe against replayed / out-of-order
  deliveries; an already-`settled` purchase is never downgraded or voided.

## Webhook → store mapping

| BTCPay event        | Backend action                     | Purchase status |
|---------------------|------------------------------------|-----------------|
| `InvoiceProcessing` | `GrantByInvoice(confirmed=false)`  | `processing`    |
| `InvoiceSettled`    | `GrantByInvoice(confirmed=true)`   | `settled`       |
| `InvoiceExpired`    | `VoidByInvoice("expired")`         | `expired`       |
| `InvoiceInvalid`    | `VoidByInvoice("invalid")`         | `invalid`       |

Other events are acked (2xx) and ignored. Unknown invoices are also acked so
BTCPay stops retrying.

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

No BTCPay needed to exercise the full HMAC-signed flow end to end:

```sh
# 1. Backend with payments pointed at the fake, autosettle OFF.
export DATABASE_URL=postgres://fips:pw@localhost:5433/fips_exit ADMIN_TOKEN=admintok
export BTCPAY_URL=http://localhost:9000 BTCPAY_API_KEY=x BTCPAY_STORE_ID=STORE1
export BTCPAY_WEBHOOK_SECRET=whsec PORTAL_PUBLIC_URL=http://localhost:8080
go run ./backend &

# 2. The fake BTCPay: serves the Greenfield invoice API + a checkout page whose
#    buttons fire signed webhooks back at the backend.
go run ./cmd/fake-btcpay -listen :9000 -base http://localhost:9000 \
  -webhook-url http://localhost:8080/payments/btcpay/webhook -secret whsec &

# 3. Log in, buy a package (redirects to the fake checkout), then click
#    "Payment detected" → the buyer's address is authorized within a poll; click
#    "Confirmed" to settle. Or drive it headless:
curl -X POST http://localhost:9000/sim/<invoice-id>/InvoiceProcessing
```

## Threat model note

Optimistic crediting means an on-chain payment that is seen but later reorged
away (or a Lightning HTLC that fails after `Processing`) can grant a brief window
of access before `Invalid` revokes it. This is bounded by usage in that window
and was accepted for UX. To harden, switch the `InvoiceProcessing` case to a
no-op and grant only on `InvoiceSettled` (one-line change in
`backend/payments_handler.go`); on-chain buyers then wait for confirmations.
