# NAC System — Demo Scenarios

Individual `curl` commands for each test scenario. Run them one by one in any terminal while the stack is up (`docker compose up -d`).

**Base URL:** `http://localhost:8000`

---

## Prerequisites

Register the PAP test user (run once):

```bash
curl -s -X POST http://localhost:8000/devices/register \
  -H 'Content-Type: application/json' \
  -d '{"device_mac":"AA:BB:CC:DD:FF:01","device_type":"pc","username":"pap_user","group":"employee"}' \
  | python3 -m json.tool
```

> The API sets `Cleartext-Password = MAC`, so the password for `pap_user` is `AA:BB:CC:DD:FF:01`.

---

## Scenario 1 — PAP Authentication (Username / Password)

### 1a. Correct credentials → `200 ACCEPT`

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"pap_user","password":"AA:BB:CC:DD:FF:01"}'
```

**Expected:** `HTTP 200`

---

### 1b. Wrong password → `401 REJECT`

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"pap_user","password":"WrongPassword"}'
```

**Expected:** `HTTP 401`

---

### 1c. Non-existent user → `401 REJECT`

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"hacker","password":"password"}'
```

**Expected:** `HTTP 401`

---

## Scenario 2 — MAB (MAC Authentication Bypass)

> MAB is used for IoT devices that cannot present a username/password.  
> The device MAC address is sent as `Calling-Station-Id`.

### 2a. Whitelisted device → `200 ACCEPT`

Device `00:11:22:33:44:01` is already in the whitelist.

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/auth \
  -H 'Content-Type: application/json' \
  -d '{"Calling-Station-Id":"00:11:22:33:44:01","User-Name":"00:11:22:33:44:01","User-Password":"00:11:22:33:44:01"}'
```

**Expected:** `HTTP 200`

---

### 2b. Rogue device NOT in whitelist → `401 REJECT`

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/auth \
  -H 'Content-Type: application/json' \
  -d '{"Calling-Station-Id":"DE:AD:BE:EF:CA:FE","User-Name":"DE:AD:BE:EF:CA:FE","User-Password":"DE:AD:BE:EF:CA:FE"}'
```

**Expected:** `HTTP 401`

---

### 2c. Add rogue device to whitelist

```bash
curl -s -X POST http://localhost:8000/whitelist \
  -H 'Content-Type: application/json' \
  -d '{"mac_address":"DE:AD:BE:EF:CA:FE","description":"Newly approved IoT device"}' \
  | python3 -m json.tool
```

**Expected:** `{"message": "device_whitelisted", "mac_address": "DE:AD:BE:EF:CA:FE"}`

---

### 2d. Retry same device after whitelisting → `200 ACCEPT`

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/auth \
  -H 'Content-Type: application/json' \
  -d '{"Calling-Station-Id":"DE:AD:BE:EF:CA:FE","User-Name":"DE:AD:BE:EF:CA:FE","User-Password":"DE:AD:BE:EF:CA:FE"}'
```

**Expected:** `HTTP 200`

---

## Bonus — Inspect Access Logs

View the last 10 decisions made by the NAC system:

```bash
curl -s http://localhost:8000/logs/access?limit=10 \
  | python3 -c "
import sys, json
for l in json.load(sys.stdin):
    icon = '✅' if l['status']=='ACCEPT' else '❌'
    print(f\"{icon} {l['status']:6} | {l['source']:10} | {l.get('mac_address') or l.get('username',''):20} | {l['reason']}\")
"
```

---

## Scenario 3 — IoT Telemetry (CoAP Ingest Flow)

This scenario tests the ingestion of sensor telemetry data (simulating CoAP packets forwarded to the API). Only whitelisted devices are allowed to submit telemetry.

### 3a. Untrusted device → `403 Forbidden`

Attempt to send telemetry from a rogue MAC `00:11:22:33:44:04` (which is not whitelisted or disabled):

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/iot/telemetry \
  -H 'Content-Type: application/json' \
  -d '{"device_mac":"00:11:22:33:44:04","payload":"temp=27.2"}'
```

**Expected:** `HTTP 403`

---

### 3b. Trusted device → `202 Accepted`

Send telemetry from a whitelisted MAC `00:11:22:33:44:01`:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/iot/telemetry \
  -H 'Content-Type: application/json' \
  -d '{"device_mac":"00:11:22:33:44:01","payload":"temp=24.5"}'
```

**Expected:** `HTTP 202`

---

### 3c. Real background Cooja-triggered telemetry simulation

To test the end-to-end simulation flow where Contiki-NG motes running in Cooja periodically generate telemetry and send them through the border router:

1. **Verify or start Cooja in headless mode:**
   ```bash
   curl -s -X POST "http://localhost:8000/cooja/start?gui=false"
   ```

2. **Watch the live output log stream:**
   ```bash
   curl -s "http://localhost:8000/cooja/logs?tail=20" | python3 -m json.tool
   ```

   * **Whitelisted nodes** (`mote_1`, `mote_2`, `mote_3` i.e. `00:11:22:33:44:01-03`) will show `[SYSTEM] Forwarded telemetry`.
   * **Disabled nodes** (like `00:11:22:33:44:04`) will show `[SYSTEM] Telemetry forward failed 403: {"detail":"Device not whitelisted"}`.

3. **Stop the background simulation runner:**
   ```bash
   curl -s -X POST "http://localhost:8000/cooja/stop"
   ```

---

## Bonus — Disable a Whitelisted Device

Remove a device from the whitelist (NAC will REJECT it on next attempt):

```bash
# Disable
curl -s -X DELETE http://localhost:8000/whitelist/00:11:22:33:44:04 \
  | python3 -m json.tool

# Verify it is now rejected
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/auth \
  -H 'Content-Type: application/json' \
  -d '{"Calling-Station-Id":"00:11:22:33:44:04","User-Name":"00:11:22:33:44:04","User-Password":"00:11:22:33:44:04"}'
```

**Expected:** `HTTP 401`

---

## Full Automated Run

Run all scenarios at once with pass/fail output:

```bash
bash scripts/demo_test.sh
```
