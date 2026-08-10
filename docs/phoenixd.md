# Payments — phoenixd (direct Lightning)

An alternative to [BTCPay](phase4-btcpay.md) for operators who just want to
accept **Lightning** and would rather not run the whole BTCPay stack. It talks
directly to an [ACINQ **phoenixd**](https://phoenix.acinq.co/server) node — a
single self-custodial binary that manages channels/liquidity automatically (no
bitcoind, no channel ops).

Select it with `PAYMENT_RAIL=phoenixd`.

```
buyer ──/buy──▶ portal ──/createinvoice──▶ phoenixd ──▶ Lightning
   ▲                │  BOLT11
   │  /pay/{id}     ▼
   └── pays with any Lightning wallet
portal ◀── payment_received webhook (signed) ── phoenixd   (+ poll reconciler)
```

## Tradeoffs vs BTCPay

- **Lightning only** — no on-chain BTC, no Monero (that's what BTCPay's weight
  buys). Lightning is final on receipt, so there's no confirmation/optimistic
  logic — a verified payment grants access immediately.
- **Minimal ops** — one binary, automated liquidity via ACINQ as LSP; reachable
  behind NAT/Tor with no public node.
- **Receiving fees & minimums** — because ACINQ provides liquidity, receiving
  costs a service/liquidity fee (and a mining-fee component when a splice is
  needed). Price packages **above** that floor; very small (sub-~1000-sat)
  packages may not be viable. Check the current phoenixd/ACINQ fee schedule.
- **Counterparty** — self-custodial (you hold the seed), but ACINQ is a required
  LSP; if sovereignty matters, BTCPay against your own node avoids that.

## Settlement model

Two paths land on the same idempotent store seam (`GrantByInvoice`), so a
payment settles reliably:

1. **Webhook** — phoenixd POSTs `payment_received` to
   `${PORTAL_PUBLIC_URL}/payments/phoenixd/webhook`, HMAC-signed
   (`X-Phoenix-Signature`, key = `PHOENIXD_WEBHOOK_SECRET`). Grants immediately.
2. **Reconciler** — a background loop polls phoenixd
   (`GET /payments/incoming/{hash}`) for open Lightning purchases, so a missed or
   differently-signed webhook still settles, and unpaid invoices are **expired**
   after `PHOENIXD_INVOICE_TTL_S`.

The buyer sees the BOLT11 on the portal's own `/pay/{id}` page (copy + a
`lightning:` link) which polls until paid, then sends them to the dashboard.

## Configure

phoenixd side (`~/.phoenix/phoenix.conf`):

```
http-password=<the PHOENIXD_PASSWORD you set>
webhook-url=http://<backend>:8080/payments/phoenixd/webhook
webhook-secret=<the PHOENIXD_WEBHOOK_SECRET you set>
```

backend (`backend.env`):

```sh
PAYMENT_RAIL=phoenixd
PHOENIXD_URL=http://127.0.0.1:9740
PHOENIXD_PASSWORD=...
PHOENIXD_WEBHOOK_SECRET=...
# PHOENIXD_SOCKS5=127.0.0.1:9050   # if phoenixd/backend are split and reached over Tor
```

The backend refuses to start with `PAYMENT_RAIL=phoenixd` if
`PHOENIXD_WEBHOOK_SECRET` is empty (an unsigned webhook would be forgeable). The
reconciler is the safety net if your phoenixd version signs webhooks differently
— payments still settle by polling; verify `X-Phoenix-Signature` against your
version and adjust if needed.

## Going live (production bring-up)

Switching a node from the fake rail to a real phoenixd node. Assumes the backend
runs **host-networked** via `backend-compose.yaml` (so it reaches phoenixd on
`127.0.0.1:9740` and phoenixd reaches the backend on `127.0.0.1:8080`).

**1. Run phoenixd on the backend host.** Grab the latest [ACINQ phoenixd](https://github.com/ACINQ/phoenixd)
release (a single binary) and start it once:

```sh
./phoenixd    # first start creates ~/.phoenix/ and prints your seed + API password
```

> ⚠️ **Back up the seed** (the 12 words it prints / `~/.phoenix/seed.dat`) offline
> **before taking any payment**. It is self-custodial — the seed *is* the money;
> lose it and the balance is gone. The HTTP API defaults to `127.0.0.1:9740`.

**Keep it running under systemd** so it restarts on failure and survives reboots.
The repo ships a unit at [`deploy/systemd/phoenixd.service`](../deploy/systemd/phoenixd.service):

```sh
sudo install -Dm755 ./phoenixd /usr/local/bin/phoenixd
sudo install -Dm644 deploy/systemd/phoenixd.service /etc/systemd/system/phoenixd.service
sudoedit /etc/systemd/system/phoenixd.service   # set User=/HOME= to the account owning ~/.phoenix
sudo systemctl daemon-reload
sudo systemctl enable --now phoenixd
journalctl -u phoenixd -f
```

Do the **first run manually** (the `./phoenixd` above) so the seed prints to your
terminal and you back it up — don't let the first start happen under systemd, or
the seed lands in the journal. Once initialized, the unit just runs the existing
node. For a throwaway test, `nohup ./phoenixd >/var/log/phoenixd.log 2>&1 &` is
fine.

**2. Configure `~/.phoenix/phoenix.conf`**, then restart phoenixd:

```ini
http-password=<the one generated on first run — reuse it>
webhook-url=http://127.0.0.1:8080/payments/phoenixd/webhook
webhook-secret=<openssl rand -hex 32>
```

**3. Point the backend at it — in `deploy/backend.env`:**

```sh
PAYMENT_RAIL=phoenixd
PHOENIXD_URL=http://127.0.0.1:9740
PHOENIXD_PASSWORD=<the http-password>
PHOENIXD_WEBHOOK_SECRET=<the webhook-secret>
```

The backend **refuses to start** with `PAYMENT_RAIL=phoenixd` and an empty
`PHOENIXD_WEBHOOK_SECRET` (forgeable-webhook fail-safe).

**4. Restart the backend and retire the fake:**

```sh
cd deploy && set -a; . ./backend.env; set +a
docker compose -f backend-compose.yaml up -d
docker rm -f fake-btcpay
docker logs fips-exit-backend-backend-1 2>&1 | grep -iE 'phoenixd|payment|reconcil|listen'
```

**5. Smoke test with a real payment.** Buy the cheapest package from the portal,
pay the BOLT11 on the `/pay/{id}` page with any Lightning wallet, and confirm the
entitlement appears in `/admin/authz` within a couple of seconds (webhook) or one
poll interval (reconciler). Note the **first-ever receive also pays a one-time
channel-funding fee**, so test with a viable amount, not dust.

**6. Verify the webhook path.** phoenixd's webhook signature scheme can differ by
version. If the immediate webhook grant doesn't fire, the **reconciler still
settles by polling** (`PHOENIXD_POLL_INTERVAL_S`), so nothing gets stuck — then
check the backend log for the webhook handler result and adjust `VerifyPhoenixSig`
if your version signs differently.

**Operations & rollback.** Receiving costs an ACINQ service/liquidity fee, so keep
prices above the floor (this is why sub-~1000-sat promos aren't offered on the
live rail). Watch the phoenixd balance and the reconciler metrics
(`{type,result}`). To roll back, set `PAYMENT_RAIL=` (or `btcpay`) in
`backend.env` and `compose up -d`.

## Local test with `cmd/fake-phoenixd`

No node needed to exercise the whole flow end to end:

```sh
# backend pointed at the fake, rail = phoenixd:
export PAYMENT_RAIL=phoenixd PHOENIXD_URL=http://127.0.0.1:9740 PHOENIXD_PASSWORD=x
export PHOENIXD_WEBHOOK_SECRET=whsec PORTAL_PUBLIC_URL=http://localhost:8080
go run ./backend &

# the fake node: serves /createinvoice + /payments/incoming, and /sim/{hash}/pay
# fires the signed webhook:
go run ./cmd/fake-phoenixd -listen :9740 \
  -webhook-url http://127.0.0.1:8080/payments/phoenixd/webhook -secret whsec &

# log in, buy a package -> the /pay page shows a fake BOLT11 and its payment hash
# (see the fake-phoenixd log). Simulate the payment:
curl -X POST http://127.0.0.1:9740/sim/<payment-hash>/pay
# -> webhook fires, access is granted, the /pay page redirects to the dashboard.
```
