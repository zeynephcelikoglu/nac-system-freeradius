#!/usr/bin/env bash
set -euo pipefail
API="${API_URL:-http://localhost:8000}"

declare -a DEVICES=(
  "00:11:22:33:44:55,cooja_mote,iot"
  "00:11:22:33:44:01,cooja_mote_1,iot"
  "00:11:22:33:44:02,cooja_mote_2,iot"
  "00:11:22:33:44:03,cooja_mote_3,iot"
  "00:11:22:33:44:04,cooja_mote_4,iot"
  "02:AA:BB:CC:DD:EE,phone,phone"
  "02:12:34:56:78:9A,laptop,pc"
)

for entry in "${DEVICES[@]}"; do
  IFS=',' read -r mac name dtype <<< "$entry"
  echo "Registering $mac as $name ($dtype)"
  curl -s -X POST "${API}/devices/register" \
    -H 'Content-Type: application/json' \
    -d '{"device_mac":"'"${mac}"'","device_type":"'"${dtype}"'","username":"'"${name}"'","group":"devices"}' | jq || true
done

echo "Done."
