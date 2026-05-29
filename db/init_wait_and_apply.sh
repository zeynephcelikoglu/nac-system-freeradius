#!/usr/bin/env bash
set -euo pipefail
# Lightweight helper: wait for Postgres then apply db/init.sql
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SQL_FILE="${ROOT_DIR}/init.sql"

DB_URL="${DATABASE_URL:-postgresql://nac_admin:nac_pass@localhost:5432/nac_db}"
POSTGRES_USER="${POSTGRES_USER:-nac_admin}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-nac_pass}"
POSTGRES_DB="${POSTGRES_DB:-nac_db}"

export PGPASSWORD="${POSTGRES_PASSWORD}"

echo "Waiting for Postgres..."
until psql "$DB_URL" -c '\l' >/dev/null 2>&1; do
  sleep 1
done

echo "Applying ${SQL_FILE}"
psql "$DB_URL" -f "$SQL_FILE"
