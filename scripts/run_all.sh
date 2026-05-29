#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

API_URL="http://localhost:8000"
RUNNER_URL="http://127.0.0.1:5001"
COMPOSE_FILE="docker-compose.dev.yml"

wait_for_http() {
  local url="$1"
  local needle="$2"
  local tries="${3:-60}"
  local delay="${4:-1}"

  for _ in $(seq 1 "$tries"); do
    if curl -sS "$url" 2>/dev/null | grep -q "$needle"; then
      return 0
    fi
    sleep "$delay"
  done

  return 1
}

echo "[run_all] Starting development stack with ${COMPOSE_FILE}"
docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
docker compose -f "$COMPOSE_FILE" up --build -d

echo "[run_all] Waiting for API to become healthy..."
if wait_for_http "$API_URL/health" '"status":"ok"' 60 1; then
  echo "[run_all] API is up"
else
  echo "[run_all] API did not become healthy in time"
fi

echo "[run_all] Waiting for runner service on ${RUNNER_URL}..."
if wait_for_http "$RUNNER_URL/status" '"running":false' 60 1 || wait_for_http "$RUNNER_URL/status" '"running":true' 60 1; then
  echo "[run_all] Runner responded"
else
  echo "[run_all] Runner service did not respond in time"
fi

echo "[run_all] Registering demo devices..."
chmod +x scripts/register_demo_devices.sh
./scripts/register_demo_devices.sh || true

echo "[run_all] Starting Cooja (headless) via runner..."
# Start Cooja headless via runner; if runner fails, try host-runner script
if curl -s -X POST "${RUNNER_URL}/start?gui=false" | grep -q 'started'; then
  echo "[run_all] Runner started Cooja"
else
  echo "[run_all] Runner start did not report started; attempting host-runner fallback"
  if [ -x tools/cooja-runner/run.sh ]; then
    tools/cooja-runner/run.sh start || true
  fi
fi

echo "[run_all] Waiting for Cooja to actually start..."
if wait_for_http "$RUNNER_URL/status" '"running":true' 120 2; then
  echo "[run_all] Cooja is running"
else
  echo "[run_all] Cooja did not report running in time; recent logs:"
  curl -s "$RUNNER_URL/logs?tail=50" || true
fi

echo "[run_all] Triggering simulated telemetry"
chmod +x scripts/run_demo.sh
./scripts/run_demo.sh || true

echo "[run_all] Opening a live demo accounting session"
DEMO_SESSION_ID="demo-$(date +%s)"
curl -s -X POST "$API_URL/accounting" \
  -H 'Content-Type: application/json' \
  -d '{
    "Acct-Status-Type": "Start",
    "Acct-Session-Id": "'"${DEMO_SESSION_ID}"'",
    "User-Name": "00:11:22:33:44:55",
    "NAS-IP-Address": "127.0.0.1",
    "Calling-Station-Id": "00:11:22:33:44:55"
  }' >/dev/null || true

echo "[run_all] Live demo session id: ${DEMO_SESSION_ID}"

echo "[run_all] Optionally running RADIUS auth simulation (can be disabled by setting NO_RAD=1)"
if [ "${NO_RAD:-0}" != "1" ]; then
  chmod +x scripts/simulate_radius.sh
  ./scripts/simulate_radius.sh || true
else
  echo "[run_all] Skipping RADIUS simulation (NO_RAD=1)"
fi

echo "[run_all] Waiting 2s for API to ingest telemetry"
sleep 2

echo "[run_all] Latest telemetry (limit 10):"
curl -s "$API_URL/iot/telemetry?limit=10" | jq || true

echo "[run_all] Latest access logs (limit 10):"
curl -s "$API_URL/logs/access?limit=10" | jq || true

echo "[run_all] Active sessions:"
curl -s "$API_URL/sessions/active" | jq || true

echo "[run_all] All started. To follow logs:"
echo "  docker compose -f ${COMPOSE_FILE} logs -f nac_api cooja_runner nac_coap_bridge"
echo "  curl ${RUNNER_URL}/logs?tail=200"

echo "[run_all] Finished."
