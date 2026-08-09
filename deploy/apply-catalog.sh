#!/bin/sh
# Apply the current package catalog to a running backend via the admin API.
#
# Deactivates every currently-active package, then creates the desired set:
#   Unlimited — 1 day pass            2000 sats
#   50 GB / 30 days                   5000 sats
#   500 GB / 90 days                 15000 sats
#   Unlimited — 30 day pass          10000 sats
#   Unlimited — 1 day pass (special)    21 sats   (promo, auto-hidden after 30 days)
#
# Prices are in sats. The special uses available_days=30, so the catalog hides it
# 30 days from when this runs; anyone who bought it keeps their pass.
#
# Requires the backend to run code with the DELETE /admin/packages/{id} and
# available_days support (migration 0004+). Run ONCE.
#
# Usage:  URL=http://127.0.0.1:8080 ADMIN_TOKEN=... sh deploy/apply-catalog.sh
# Needs:  curl, jq.
set -eu
: "${URL:?set URL, e.g. http://127.0.0.1:8080}"
: "${ADMIN_TOKEN:?set ADMIN_TOKEN}"
H="Authorization: Bearer $ADMIN_TOKEN"

echo "Deactivating existing packages..."
curl -fsS -H "$H" "$URL/admin/packages" | jq -r '.packages[].id' | while read -r id; do
  curl -fsS -H "$H" -X DELETE "$URL/admin/packages/$id" >/dev/null && echo "  - $id"
done

echo "Creating new catalog..."
create() { curl -fsS -H "$H" -X POST "$URL/admin/packages" -d "$1" >/dev/null && echo "  + $2"; }
create '{"kind":"time","name":"Unlimited — 1 day pass","days":1,"price_sats":2000}'          "Unlimited — 1 day pass (2000)"
create '{"kind":"volume","name":"50 GB / 30 days","gb":50,"days":30,"price_sats":5000}'      "50 GB / 30 days (5000)"
create '{"kind":"volume","name":"500 GB / 90 days","gb":500,"days":90,"price_sats":15000}'   "500 GB / 90 days (15000)"
create '{"kind":"time","name":"Unlimited — 30 day pass","days":30,"price_sats":10000}'       "Unlimited — 30 day pass (10000)"
create '{"kind":"time","name":"Unlimited — 1 day pass (special)","days":1,"price_sats":21,"available_days":30}' "SPECIAL 1 day pass (21, 30d)"

echo "Current catalog:"
curl -fsS -H "$H" "$URL/admin/packages" | jq -r '.packages[] | "  \(.name) — \(.price_msat/1000) sats"'
