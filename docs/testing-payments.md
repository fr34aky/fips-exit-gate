# Testing payments with the fake nodes

Exercise the full payment flow — BTCPay, Lightning (phoenixd), and Cashu — with no
real payment infrastructure: no BTCPay server, no Lightning node, no channel, no
mint. Three test doubles under `cmd/` stand in and fire the same signed webhooks
the real services do, so the backend behaves exactly as in production.

| Fake | Stands in for | Default port |
|---|---|---|
| `cmd/fake-btcpay` | BTCPay Server (on-chain BTC + Lightning + Monero) | `:9000` |
| `cmd/fake-phoenixd` | ACINQ phoenixd (direct Lightning) | `:9740` |
| `cmd/fake-cashu-mint` | a Cashu mint (accept-and-melt; drives fake-phoenixd) | `:3338` |

**Shared setup.** All flows need the backend running against a Postgres, with an
admin token and a portal URL. The `-secret` each fake signs with **must equal**
the backend's webhook secret for that rail (`BTCPAY_WEBHOOK_SECRET` /
`PHOENIXD_WEBHOOK_SECRET`), or the backend rejects the webhook. Never set
`PORTAL_DEV_AUTOSETTLE=1` here — that bypasses payments entirely and hides bugs.

---

## BTCPay (`cmd/fake-btcpay`)

Serves the Greenfield invoice API plus a checkout page whose buttons fire signed
webhooks. Access is granted **only on `InvoiceSettled`** (on-chain finalization),
not on `InvoiceProcessing`.

```sh
# 1. Backend, BTCPay rail pointed at the fake:
export DATABASE_URL=postgres://fips:pw@localhost:5432/fips_exit ADMIN_TOKEN=admintok
export PAYMENT_RAIL=btcpay BTCPAY_URL=http://localhost:9000 BTCPAY_API_KEY=x BTCPAY_STORE_ID=STORE1
export BTCPAY_WEBHOOK_SECRET=whsec PORTAL_PUBLIC_URL=http://localhost:8080
go run ./backend &

# 2. The fake BTCPay:
go run ./cmd/fake-btcpay -listen :9000 -base http://localhost:9000 \
  -webhook-url http://localhost:8080/payments/btcpay/webhook -secret whsec &
```

Log in, buy a package → you're redirected to the fake checkout (`/i/{id}`). Click
**"Confirmed (Settled)"** → access granted. ("Payment detected" → `confirming…`,
no access — that's the finalization guard.) Or drive it headless:

```sh
curl -X POST http://localhost:9000/sim/<invoice-id>/InvoiceProcessing   # confirming, no access
curl -X POST http://localhost:9000/sim/<invoice-id>/InvoiceSettled      # finalized -> access
```

---

## Lightning + Cashu (`cmd/fake-phoenixd` + `cmd/fake-cashu-mint`)

`fake-phoenixd` issues fake BOLT11 invoices and fires the `payment_received`
webhook on `/sim/{hash}/pay`. `fake-cashu-mint` implements the NUT-05 melt and, on
melt, **drives fake-phoenixd's `/sim`** so a Cashu payment settles just like a
Lightning one.

```sh
# 1. Fake Lightning node:
go run ./cmd/fake-phoenixd -listen :9740 \
  -webhook-url http://127.0.0.1:8080/payments/phoenixd/webhook -secret whsec &

# 2. Fake Cashu mint (drives the fake node above — note the matching port):
go run ./cmd/fake-cashu-mint -listen :3338 \
  -phoenixd-url http://127.0.0.1:9740 -mint-url http://127.0.0.1:3338 &

# 3. Backend, phoenixd rail + Cashu enabled:
export DATABASE_URL=postgres://fips:pw@localhost:5432/fips_exit ADMIN_TOKEN=admintok
export PAYMENT_RAIL=phoenixd PHOENIXD_URL=http://127.0.0.1:9740 PHOENIXD_PASSWORD=x \
  PHOENIXD_WEBHOOK_SECRET=whsec PORTAL_PUBLIC_URL=http://localhost:8080 CASHU_ACCEPT=1
go run ./backend &
```

> **Port-matching rule (the #1 gotcha):**
> `fake-cashu-mint -phoenixd-url` **==** backend `PHOENIXD_URL` **==** `fake-phoenixd -listen`.
> If the mint points at a different phoenixd than the one the backend created the
> invoice on, its `/sim` call fails and the melt returns `mint HTTP 502`.

Buy a package; the `/pay/{id}` page shows a fake BOLT11 (+ QR) and, with
`CASHU_ACCEPT=1`, a Cashu payment-request QR + paste box.

- **Lightning** — the invoice is `lnbcrt-fake-<hash>` (the hash is in the
  fake-phoenixd log):
  ```sh
  curl -X POST http://127.0.0.1:9740/sim/<hash>/pay      # webhook -> granted
  ```
- **Cashu (paste)** — mint yourself a token for the exact package price and paste
  it on the pay page:
  ```sh
  curl "http://127.0.0.1:3338/sim/token?amount=<package-price-sats>"   # -> cashuA…
  ```
- **Cashu (NUT-18 receive)** — simulate a wallet POSTing to the transport target:
  ```sh
  curl -X POST http://127.0.0.1:8080/pay/<purchase-id>/cashu-receive \
    -H 'Content-Type: application/json' \
    -d '{"mint":"http://127.0.0.1:3338","unit":"sat","proofs":[{"amount":<price>,"id":"00ffffffffffffff","secret":"x","C":"02"}]}'
  ```

---

## Running the fakes on a deployed node

You can test on a live node too — run the fakes on the host and point `backend.env`
at them (the host-networked backend reaches them on loopback), then restart just
the backend:

```sh
docker compose -f backend-compose.yaml up -d backend
```

**Watch the ports.** A real phoenixd already holds `:9740`, so either stop it
(`systemctl stop phoenixd`) or run `fake-phoenixd` on a free port (e.g. `:9750`)
and set **both** the backend's `PHOENIXD_URL` and `fake-cashu-mint -phoenixd-url`
to that port. Reuse the real `PHOENIXD_WEBHOOK_SECRET` as the fake's `-secret` so
the backend verifies its webhook without touching `backend.env`.

Revert when done: restore `PHOENIXD_URL` (and `CASHU_ACCEPT`), kill the fakes,
restart the real phoenixd, and `compose up -d backend`.

> The fakes are for testing only — never expose them on a real deployment's public
> interfaces. See also [BTCPay](phase4-btcpay.md) and [phoenixd](phoenixd.md).
