#!/usr/bin/env bash
# =============================================================
# NAC System — Demo Test Scenarios (Full Run)
# Usage: bash scripts/demo_test.sh
# Runs all scenarios automatically; for individual commands see:
#   docs/demo_scenarios.md
# =============================================================
set -euo pipefail

API="${API_URL:-http://localhost:8000}"
MALICIOUS_MAC="DE:AD:BE:EF:CA:FE"   # device NOT in whitelist (simulates rogue device)
LEGIT_MAC="00:11:22:33:44:01"        # device already in whitelist (Cooja node)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

sep()  { echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
step() { echo -e "\n${YELLOW}▶ $1${NC}"; }
ok()   { echo -e "${GREEN}✅ $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; }

# ── Setup: register PAP test user ───────────────────────────
sep
PAP_MAC="AA:BB:CC:DD:FF:01"
PAP_USER="pap_user"
PAP_PASS="${PAP_MAC}"   # /devices/register sets Cleartext-Password = MAC

step "SETUP: Registering PAP test user (${PAP_USER} / password=${PAP_PASS})"
curl -s -X POST "${API}/devices/register" \
  -H 'Content-Type: application/json' \
  -d "{\"device_mac\":\"${PAP_MAC}\",\"device_type\":\"pc\",\"username\":\"${PAP_USER}\",\"group\":\"employee\"}" \
  | python3 -m json.tool 2>/dev/null || true
ok "User ready: ${PAP_USER} / password=${PAP_PASS}"
sleep 0.5

# ════════════════════════════════════════════════════════════
# SCENARIO 1 — PAP Authentication
# ════════════════════════════════════════════════════════════
sep
echo -e "${BLUE}SCENARIO 1: PAP (Username / Password) Authentication${NC}"

step "1a) PAP — Correct password → ACCEPT expected"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API}/auth" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${PAP_USER}\",\"password\":\"${PAP_PASS}\"}")
[ "$HTTP" = "200" ] && ok "HTTP $HTTP — ACCEPT" || fail "HTTP $HTTP — Unexpected response"

step "1b) PAP — Wrong password → REJECT expected"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API}/auth" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${PAP_USER}\",\"password\":\"WrongPassword123\"}")
[ "$HTTP" = "401" ] && ok "HTTP $HTTP — REJECT" || fail "HTTP $HTTP — Unexpected response"

step "1c) PAP — Non-existent user → REJECT expected"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API}/auth" \
  -H 'Content-Type: application/json' \
  -d '{"username":"hacker","password":"password"}')
[ "$HTTP" = "401" ] && ok "HTTP $HTTP — REJECT" || fail "HTTP $HTTP — Unexpected response"

# ════════════════════════════════════════════════════════════
# SCENARIO 2 — MAB (MAC Authentication Bypass) Flow
# ════════════════════════════════════════════════════════════
sep
echo -e "${BLUE}SCENARIO 2: MAB (IoT Device MAC Authentication) Flow${NC}"

# Reset: remove MALICIOUS_MAC from whitelist to ensure clean state on re-runs
curl -s -o /dev/null -X DELETE "${API}/whitelist/${MALICIOUS_MAC}" || true

step "2a) MAB — Whitelisted device (${LEGIT_MAC}) → ACCEPT expected"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API}/auth" \
  -H 'Content-Type: application/json' \
  -d "{\"Calling-Station-Id\":\"${LEGIT_MAC}\",\"User-Name\":\"${LEGIT_MAC}\",\"User-Password\":\"${LEGIT_MAC}\"}")
[ "$HTTP" = "200" ] && ok "HTTP $HTTP — ACCEPT" || fail "HTTP $HTTP — Unexpected response"

step "2b) MAB — Rogue device NOT in whitelist (${MALICIOUS_MAC}) → REJECT expected"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API}/auth" \
  -H 'Content-Type: application/json' \
  -d "{\"Calling-Station-Id\":\"${MALICIOUS_MAC}\",\"User-Name\":\"${MALICIOUS_MAC}\",\"User-Password\":\"${MALICIOUS_MAC}\"}")
[ "$HTTP" = "401" ] && ok "HTTP $HTTP — REJECT (MAC not in whitelist)" || fail "HTTP $HTTP — Unexpected response"

step "2c) Adding rogue device to whitelist (${MALICIOUS_MAC})..."
curl -s -X POST "${API}/whitelist" \
  -H 'Content-Type: application/json' \
  -d "{\"mac_address\":\"${MALICIOUS_MAC}\",\"description\":\"Newly approved device\"}" \
  | python3 -m json.tool 2>/dev/null || true
ok "Added to whitelist"
sleep 0.3

step "2d) MAB — Retry with same device (${MALICIOUS_MAC}) → ACCEPT expected"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API}/auth" \
  -H 'Content-Type: application/json' \
  -d "{\"Calling-Station-Id\":\"${MALICIOUS_MAC}\",\"User-Name\":\"${MALICIOUS_MAC}\",\"User-Password\":\"${MALICIOUS_MAC}\"}")
[ "$HTTP" = "200" ] && ok "HTTP $HTTP — ACCEPT (device now whitelisted)" || fail "HTTP $HTTP — Unexpected response"

# ════════════════════════════════════════════════════════════
# SUMMARY — Access Log
# ════════════════════════════════════════════════════════════
sep
echo -e "${BLUE}SUMMARY: Recent access log entries${NC}"
curl -s "${API}/logs/access?limit=10" \
  | python3 -c "
import sys, json
logs = json.load(sys.stdin)
for l in logs:
    icon = '✅' if l['status']=='ACCEPT' else '❌'
    print(f\"{icon} {l['status']:6} | {l['source']:10} | {l.get('mac_address') or l.get('username',''):20} | {l['reason']}\")
"

sep
echo -e "${GREEN}Demo complete! View results on the dashboard: http://localhost:8000${NC}"
