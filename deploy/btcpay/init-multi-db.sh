#!/bin/sh
# Create the btcpay and nbxplorer databases on first Postgres init.
set -eu
for db in btcpay nbxplorer; do
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
        SELECT 'CREATE DATABASE $db' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$db')\gexec
EOSQL
done
