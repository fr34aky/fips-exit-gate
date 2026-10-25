# Observability

Every service exposes Prometheus metrics in the text exposition format. The
implementation is a tiny stdlib-only registry (`pkg/metrics`) — no metrics
library — so the agent and captive daemon stay dependency-free and
OpenWrt-portable.

## Enabling /metrics

| Service | Endpoint | How to enable |
|---|---|---|
| **backend** | `GET /metrics` on the API port (`:8080`) | Always registered. Optionally gate with `METRICS_TOKEN` (Prometheus scrapes with a bearer token); otherwise restrict by network/reverse-proxy. |
| **agent** | `GET /metrics` on `FIPS_AGENT_METRICS_ADDR` | Set the env var (e.g. `:9101`). Empty = disabled. |
| **captive** | `GET /metrics` on `CAPTIVE_METRICS_ADDR` | Set the env var (e.g. `:9102`). Empty = disabled. |

Bind the agent/captive metrics addresses to a management interface, not the
public one.

## Health endpoints (backend)

| Path | Meaning |
|---|---|
| `GET /healthz` | The process is up and serving (200 `ok`). For load balancers. |
| `GET /readyz` | Additionally pings the database and checks every embedded migration is applied (200 `ready`, else 503 with the reason). Use it as the compose/systemd/orchestrator readiness probe and after upgrades. |

Both are unauthenticated and served on the public listener.

## Logging

Every binary logs through `log/slog`. `LOG_FORMAT=json` switches from the
default text lines to one JSON object per record (`time`, `level`, `msg`,
`service`), `LOG_LEVEL` (`debug|info|warn|error`, default `info`) filters.
Existing `log.Printf` lines appear as `INFO` records, so nothing is lost on the
way to a structured pipeline.

## Metrics catalog

**Backend** (`fipsexit_`)

| Metric | Type | Notes |
|---|---|---|
| `fipsexit_store_up` | gauge | 1 if Postgres was reachable at scrape time. |
| `fipsexit_authorized_addresses` | gauge | Size of the authorized set. |
| `fipsexit_authz_revision` | counter | Current global authz revision. |
| `fipsexit_entitlements_active` | gauge | Active (unexpired, unexhausted) entitlements. |
| `fipsexit_usage_bytes_total` | counter | Total metered bytes ingested. |
| `fipsexit_accounts{status}` | gauge | Accounts by status. |
| `fipsexit_purchases{status}` | gauge | Purchases by status (pending/processing/settled/invalid/expired). |
| `fipsexit_exit_node_last_seen_seconds{node}` | gauge | Unix time of a node's last heartbeat (0 = never). |
| `fipsexit_webhook_events_total{type,result}` | counter | BTCPay webhooks by event type and result (`ok`/`unknown_invoice`/`ignored`/`bad_signature`/`bad_request`/`error`). |
| `fipsexit_goroutines`, `fipsexit_memory_alloc_bytes`, `fipsexit_gc_total` | — | Go runtime. |

**Agent** (`fipsexit_agent_`)

| Metric | Type | Notes |
|---|---|---|
| `fipsexit_agent_authorized_addresses` | gauge | Addresses in the kernel authorized set. |
| `fipsexit_agent_authz_revision` | gauge | Last applied authz revision. |
| `fipsexit_agent_last_sync_seconds` | gauge | Unix time of the last successful authz sync. |
| `fipsexit_agent_backend_up` | gauge | 1 if the backend was reachable on the last sync attempt. |
| `fipsexit_agent_fail_open_active` | gauge | 1 while the backend is unreachable and the last-known set is retained. |
| `fipsexit_agent_sync_errors_total` | counter | Authz sync errors. |
| `fipsexit_agent_nft_errors_total` | counter | nftables operation errors. |
| `fipsexit_agent_usage_reports_sent_total` | counter | Usage reports delivered. |
| `fipsexit_agent_usage_reports_buffered` | gauge | Reports currently buffered on disk. |
| `fipsexit_agent_usage_reports_dropped_total` | counter | Reports dropped (buffer full). |
| `fipsexit_agent_usage_last_collect_seconds` | gauge | Unix time of the last successful read of the `acct` counters. The stall alert watches this (idle customers are not a stall). |
| `fipsexit_agent_usage_bytes_total` | counter | Bytes collected from the counters since start, all services. |
| `fipsexit_agent_usage_collect_errors_total` | counter | Failed counter reads (table missing, `nft` failing). |

**Captive** (`fipsexit_captive_`)

| Metric | Type | Notes |
|---|---|---|
| `fipsexit_captive_connections_total` | counter | Connections accepted and handled. |
| `fipsexit_captive_redirects_total` | counter | HTTP 302 redirects issued. |
| `fipsexit_captive_refused_total` | counter | Non-HTTP / non-CONNECT / error. |
| `fipsexit_captive_shed_total` | counter | Connections dropped at max capacity. |

## Scraping and alerts

Example configs are in [`deploy/monitoring/`](../deploy/monitoring):
`prometheus.yml` (scrape jobs for backend/agent/captive) and `alerts.yml`
(alerting rules). Point Prometheus at your hosts and load the rules:

```sh
# in prometheus.yml
rule_files:
  - alerts.yml
```

The bundled alerts cover: a target down, backend↔DB down, an exit node stale
(no heartbeat > 5m), the agent unable to reach the backend (fail-open), a usage
stall (authorized users but no reports), usage buffering (delivery failing), and
BTCPay webhook failures.

## Quick check

```sh
curl -s http://backend:8080/metrics | grep '^fipsexit_'
curl -s http://exit-01:9101/metrics | grep '^fipsexit_agent_'
```
