#!/usr/bin/env bash
set -euo pipefail
API="${API_URL:-http://localhost:8000}"
DEVICE="${DEVICE_MAC:-00:11:22:33:44:55}"
COUNT="${COUNT:-3}"
INTERVAL="${INTERVAL_MS:-500}"

echo "Ensuring device ${DEVICE} is whitelisted..."
curl -s -X POST "${API}/whitelist" -H 'Content-Type: application/json' -d '{"mac_address": "'"${DEVICE}"'", "description": "demo_auto_whitelist"}' >/dev/null || true
sleep 0.5

echo "Calling ${API}/simulate device=${DEVICE} count=${COUNT} interval_ms=${INTERVAL}"
curl -s -X POST "${API}/simulate?count=${COUNT}&interval_ms=${INTERVAL}&device_mac=${DEVICE}" | jq || true
