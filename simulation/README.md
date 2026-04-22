    # Simulation Runbook (Cooja + Border Router + Tunslip6 + CoAP)

This document describes the simulation side of the NAC project for Linux and macOS (Apple Silicon).

## Topology

- Cooja/Contiki-NG nodes generate IoT traffic.
- Border Router connects the 6LoWPAN side to host networking.
- `tunslip6` bridges the IPv6 network.
- CoAP payloads go to `nac_coap_bridge` (`udp/5683`).
- Bridge forwards telemetry to FastAPI `POST /iot/telemetry`.
- FastAPI validates MAC whitelist and stores telemetry + access logs.

## 1) Start backend services

### Linux (amd64)
```bash
cd /home/baris/nac-system-freeradius
docker compose -f docker-compose.yml -f docker-compose.amd64.yml up -d --build
```

### macOS M1/M2 (arm64)
```bash
cd /home/baris/nac-system-freeradius
docker compose -f docker-compose.yml -f docker-compose.arm64.yml up -d --build
```

## 2) Prepare Contiki-NG

If not cloned yet:
```bash
cd /home/baris/nac-system-freeradius
mkdir -p simulation
git clone --depth 1 https://github.com/contiki-ng/contiki-ng.git simulation/contiki-ng
```

## 3) Run Cooja

```bash
cd /home/baris/nac-system-freeradius/simulation/contiki-ng/tools/cooja
./gradlew run
```

Use a scenario with one border-router and one or more sensor motes.

## 4) Border Router and Tunslip6

### Option A: Native border-router example

```bash
cd /home/baris/nac-system-freeradius/simulation/contiki-ng/examples/rpl-border-router
make TARGET=native
./border-router.native fd00::1/64
```

In another terminal:

```bash
cd /home/baris/nac-system-freeradius/simulation/contiki-ng/tools/serial-io
sudo ./tunslip6 -u /dev/ttyUSB0 fd00::1/64
```

Replace `/dev/ttyUSB0` with your serial device (`/dev/ttyACM0`, `/dev/cu.usbmodem*`, etc).

### Option B: Cooja simulated serial

If using Cooja serial forwarding, point `tunslip6` to the pseudo-tty emitted by Cooja.

## 5) Send CoAP telemetry (manual validation)

You can validate bridge behavior from host with a CoAP client.

Example JSON payload:

```json
{"device_mac":"00:11:22:33:44:55","payload":"temp=24.1","message_type":"confirmable","path":"/telemetry"}
```

## 6) Validate from FastAPI

```bash
curl http://localhost:8000/whitelist
curl http://localhost:8000/iot/telemetry
curl http://localhost:8000/logs/access
```

## 7) Add a new IoT device to whitelist

```bash
curl -X POST http://localhost:8000/whitelist \
  -H "Content-Type: application/json" \
  -d '{"mac_address":"AA:BB:CC:DD:EE:FF","description":"Cooja Node 2"}'
```

## Notes

- Backend containers are cross-platform via Docker compose overrides.
- Simulation and TUN/TAP components are intentionally host-native for better stability and performance.
- On Apple Silicon, `nac_radius` runs under `linux/amd64` emulation by design.
