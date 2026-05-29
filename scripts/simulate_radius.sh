#!/usr/bin/env bash
set -euo pipefail
CONTAINER_NAME=${RAD_CONTAINER:-nac_radius}
SECRET=${RADIUS_SECRET:-testing123}

function send_rad() {
  local mac=$1
  local user=$2
  local secret=$3
  local payload="User-Name=${user},User-Password=${mac},Calling-Station-Id=${mac}"

  # By default prefer API fallback to avoid accidentally talking to other freeradius containers.
  if [ "${USE_RADCLIENT:-0}" = "1" ]; then
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
      echo "Sending RADIUS auth via container ${CONTAINER_NAME} for ${mac}"
      echo "$payload" | docker exec -i ${CONTAINER_NAME} radclient -x localhost:1812 auth ${secret} || true
    elif command -v radclient >/dev/null 2>&1; then
      echo "Sending RADIUS auth via local radclient for ${mac}"
      echo "$payload" | radclient -x localhost:1812 auth ${secret} || true
    else
      echo "radclient not found and container ${CONTAINER_NAME} not running. Skipping."
    fi
  else
    echo "Using API /auth fallback for ${mac} (set USE_RADCLIENT=1 to use radclient)"
    API_URL=${API_URL:-http://localhost:8000}
    json=$(jq -n --arg un "$user" --arg pw "$mac" --arg csid "$mac" '{"username": $un, "password": $pw, "Calling-Station-Id": $csid}') 2>/dev/null || json="{\"username\":\"$user\",\"password\":\"$mac\",\"Calling-Station-Id\":\"$mac\"}"
    curl -s -X POST "$API_URL/auth" -H 'Content-Type: application/json' -d "$json" || true
  fi
}

declare -a DEVICES=("00:11:22:33:44:55" "02:AA:BB:CC:DD:EE" "02:12:34:56:78:9A")

for mac in "${DEVICES[@]}"; do
  send_rad "$mac" "$mac" "$SECRET"
done
