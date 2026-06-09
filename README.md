# Network Access Control (NAC) & IoT Telemetry System

A production-ready, containerized AAA (Authentication, Authorization, and Accounting) system built with **FreeRADIUS 3.2**, a custom **FastAPI Policy Engine**, **PostgreSQL**, and **Redis**. Integrated with a simulated IoT environment using **Contiki-NG** and **Cooja** to provide dynamic VLAN isolation, MAC Authentication Bypass (MAB), and secure IoT telemetry ingestion.

---

## 🛠️ Key Capabilities & Features

*   **RESTful Policy Decision Engine (`rlm_rest`):** Modernizes FreeRADIUS logic by routing authentication and authorization requests through a secure FastAPI microservice in real-time.
*   **Dynamic VLAN Assignment:** Dynamically isolates devices into specific VLANs (e.g., VLAN 10 for Admin, 20 for Employee, 30 for Guest/IoT) based on group rules fetched from PostgreSQL.
*   **Dual-Tier Storage Architecture:** 
    *   **PostgreSQL:** Stores persistent tables (credentials, whitelist, access/telemetry logs, RADIUS accounting data).
    *   **Redis:** Serves as a high-performance session cache to track active RADIUS sessions in real-time.
*   **MAC Authentication Bypass (MAB):** Allows secure network access for legacy or low-power IoT devices (which cannot present a username/password) by verifying their MAC addresses against a managed whitelist.
*   **CoAP Telemetry Ingestion Bridge:** Ingests lightweight Constrained Application Protocol (CoAP) telemetry packets from simulated Contiki-NG motes, validates device whitelisting via the API, and stores telemetry.
*   **Interactive Web Control Center:** A beautiful, responsive browser-based dashboard to visualize network state, manage the device whitelist, inspect active sessions, trace PAP/MAB access decisions, and control the Cooja simulator.

---

## 📂 Project Structure

```
.
├── api/                       # FastAPI Policy Engine & Web Dashboard
│   ├── static/                # Dashboard UI (HTML, CSS, JS)
│   ├── main.py                # Policy Engine routes, REST handlers, and Cooja proxy
│   ├── database.py            # PostgreSQL pool configuration
│   ├── models.py              # PostgreSQL database schemas
│   └── schemas.py             # Pydantic request/response schemas
├── coap-bridge/               # CoAP UDP (5683) to HTTP REST Bridge
│   ├── bridge.py              # Ingests CoAP payloads and forwards to API
│   └── requirements.txt
├── db/                        # Database schema & initial seeds
│   └── init.sql               # Initializes radcheck, radacct, whitelist, logs, etc.
├── docs/                      # Reference documents & guides
│   └── demo_scenarios.md      # Detailed curl commands for all test cases
├── radius/                    # FreeRADIUS 3.2 Docker configurations
│   └── config/                # REST module, default sites, and policy rules
├── scripts/                   # Automated demo & verification scripts
│   ├── run_all.sh             # Launches whole stack + simulation + tests with 1 command
│   ├── demo_test.sh           # Automated end-to-end HTTP/RADIUS test suite
│   ├── run_demo.sh            # Generates simulated telemetry bursts
│   └── simulate_radius.sh     # Sends test RADIUS auth/accounting requests
├── simulation/                # IoT Simulation environment
│   ├── contiki-ng/            # Submodule for Contiki-NG OS & Cooja
│   ├── nac_mab_demo.csc       # Cooja Network Simulation Topology XML
│   └── README.md              # Simulation guide and runbook
└── tools/                     # Cooja API wrapper
    └── cooja-runner/          # Runs Cooja in docker & forwards logs/events
```

---

## 📊 System Architecture

The following diagram illustrates how the RADIUS Authentication flow and the CoAP IoT Telemetry flow converge on the FastAPI Policy Engine:

```
      [ RADIUS AAA Flow ]                          [ IoT Telemetry Flow ]
 
   +-----------------------+                   +----------------------------+
   |  User / Legacy Device |                   |  Contiki-NG Node (Cooja)   |
   +-----------+-----------+                   +--------------+-------------+
               |                                              |
               | RADIUS Request (UDP 1812/1813)               | CoAP Telemetry (UDP 5683)
               v                                              v
       +-------+--------+                             +-------+--------+
       | FreeRADIUS 3.2 |                             |  CoAP Bridge   |
       +-------+--------+                             +-------+--------+
               |                                              |
               | (rlm_rest)                                   | HTTP POST /iot/telemetry
               +-----------------------+   +------------------+
                                       |   |
                                       v   v
                               +-------+---+----+
                               | FastAPI Engine | <------------> [ Redis 8 ]
                               |  (Port 8000)   |             (Session Cache)
                               +-------+--------+
                                       |
                                       v
                               +-------+--------+
                               |  PostgreSQL 18 |
                               | (radacct, logs,|
                               |   whitelist)   |
                               +----------------+
```

During the authorize phase, FreeRADIUS communicates with FastAPI via `rlm_rest`. FastAPI verifies credentials or whitelists, updates session tables, and returns dynamic VLAN identifiers (`Tunnel-Private-Group-Id`).

---

## ⚡ Deployment & Quickstart

You can launch the entire system—including the backend databases, FreeRADIUS, CoAP bridge, dashboard, Cooja controller, and simulated telemetry run—with a single command:

```bash
chmod +x scripts/run_all.sh
./scripts/run_all.sh
```

### Manual Service Deployment

If you prefer starting the docker containers manually:

**1. Clone the repository (specifically the updates branch) and configure environment variables:**
```bash
git clone -b feature/nac-system-updates https://github.com/zeynephcelikoglu/nac-system-freeradius.git && cd nac-system-freeradius
cp .env.example .env
```

**2. Launch the docker services according to your host operating system:**

*   **Linux (x86_64 / amd64):**
    ```bash
    docker compose -f docker-compose.yml -f docker-compose.amd64.yml up -d --build
    ```
*   **macOS (Apple Silicon M1/M2):**
    ```bash
    docker compose -f docker-compose.yml -f docker-compose.arm64.yml up -d --build
    ```
*   **Minimal/Classroom Environment:**
    ```bash
    docker compose -f docker-compose.dev.yml up -d --build
    ```

**3. Verify status:**
```bash
docker ps
```

---

## 🖥️ Web Control Center (Dashboard)

Once the stack is running, access the dashboard at:
*   **URL:** `http://localhost:8000/`
*   **Security:** By default, dashboard routes are protected with BasicAuth.
    *   **Username:** `admin`
    *   **Password:** `password` *(Configurable in `.env.dev` / `.env`)*
    *   *Note: Set `DISABLE_DASH_AUTH=1` in your environment to disable authentication.*

### Dashboard Features
*   **Whitelisted Devices:** View all MAC addresses authorized for Network Access Bypass (MAB). You can disable devices instantly.
*   **Live RADIUS Sessions:** Real-time sessions fetched directly from Redis.
*   **IoT Telemetry:** Ingestion logs showing telemetry payload values, path, and ingestion timestamp.
*   **Cooja Controls:** Start GUI/Headless simulator instances and view live Contiki-NG logs directly in the browser.
*   **Simulation Runner:** Instantly send mock telemetry packets to verify dashboard graphs without starting Cooja.

## 📶 IoT Security & Telemetry Pipeline

For low-power IoT devices that lack the resources to run full enterprise authentication protocols (like 802.1X/EAP-TLS), this system provides a dedicated security and telemetry ingestion pipeline:

```
[ Contiki-NG Mote ] ---> (CoAP UDP:5683) ---> [ CoAP Bridge ] ---> (HTTP POST /iot/telemetry) ---> [ FastAPI Engine ] ---> (Check mac_whitelist)
                                                                                                            |
                                                                                    +-----------------------+-----------------------+
                                                                                    | (If MAC Whitelisted)                          | (If MAC Rogue/Disabled)
                                                                                    v                                               v
                                                                             [ 202 Accepted ]                               [ 403 Forbidden ]
                                                                      (Saved to `iot_telemetry` table)               (Logged as Reject in `access_logs`)
```

### 1. MAC Authentication Bypass (MAB)
IoT devices are registered with their unique MAC address. When an IoT device connects:
1. The network switch (or AP) detects the connection and sends the MAC as the `Calling-Station-Id` in a RADIUS Access-Request.
2. FreeRADIUS forwards this context to FastAPI `/auth` via `rlm_rest`.
3. FastAPI checks the MAC in `mac_whitelist`. If it exists and is `enabled = true`, it returns an `ACCEPT` and assigns the device to its isolated IoT/Guest VLAN (VLAN 30) dynamically.

### 2. CoAP Ingestion and Real-time Policy Guard
When a simulated Contiki-NG device publishes telemetry:
1. The device transmits a CoAP message over UDP port `5683` containing its payload (e.g., temperature/humidity) and its MAC address.
2. The `nac_coap_bridge` container listens on UDP `5683`, parses the CoAP packet, wraps it into a standard JSON payload, and makes an HTTP POST to FastAPI `/iot/telemetry`.
3. FastAPI verifies the whitelisting status of the device in real-time.
    - **Whitelisted:** Returns `202 Accepted` and inserts the telemetry payload into the PostgreSQL `iot_telemetry` table.
    - **Non-Whitelisted/Disabled:** Returns `403 Forbidden` and logs a security incident in the `access_logs` table.

---

## 🧪 Live Demo Guide (Step-by-Step)

To demonstrate the full capability of the NAC system, follow this scenario:

### 1. Run the Automated Verification Suite
Execute the testing script which walks through every authentication scenario (PAP, MAB, Telemetry Whitelisting, and Access Log verification):
```bash
bash scripts/demo_test.sh
```

### 2. Manual PAP Authentication (User Validation)
Test PAP authentication using `radtest` to verify credential checks and VLAN mappings:
```bash
# Correct credentials (Expected: Access-Accept)
docker exec -it nac_radius radtest zeynep 123456 127.0.0.1 0 testing123

# Incorrect credentials (Expected: Access-Reject)
docker exec -it nac_radius radtest zeynep WRONGPASS 127.0.0.1 0 testing123
```

### 3. MAC Authentication Bypass (MAB) Simulation

*   **Step A: Rogue Access Attempt**
    Send a MAB request from a non-whitelisted MAC address `DE:AD:BE:EF:CA:FE`:
    ```bash
    echo "User-Name=DE:AD:BE:EF:CA:FE,User-Password=DE:AD:BE:EF:CA:FE,Calling-Station-Id=DE:AD:BE:EF:CA:FE" \
      | docker exec -i nac_radius radclient -x localhost:1812 auth testing123
    ```
    *   **Expected Response:** `Access-Reject`
    *   **Dashboard Verification:** Check the "Access Decisions" table. You will see a `REJECT` entry with reason `mac_not_whitelisted`.

*   **Step B: Approve/Whitelist the Device**
    Add the MAC to the whitelist using the form on the Web Dashboard or via `curl`:
    ```bash
    curl -s -X POST http://localhost:8000/whitelist \
      -H 'Content-Type: application/json' \
      -d '{"mac_address":"DE:AD:BE:EF:CA:FE","description":"Approved Demo Device"}'
    ```

*   **Step C: Retry Authentication**
    Re-run the MAB client command:
    ```bash
    echo "User-Name=DE:AD:BE:EF:CA:FE,User-Password=DE:AD:BE:EF:CA:FE,Calling-Station-Id=DE:AD:BE:EF:CA:FE" \
      | docker exec -i nac_radius radclient -x localhost:1812 auth testing123
    ```
    *   **Expected Response:** `Access-Accept`
    *   **Dashboard Verification:** The "Access Decisions" table will show `ACCEPT` with reason `mac_whitelisted`.

### 4. CoAP Telemetry Validation
Test the CoAP integration by sending telemetry messages. Only whitelisted devices are allowed:
```bash
# Whitelisted MAC (Expected: 202 Accepted)
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/iot/telemetry \
  -H 'Content-Type: application/json' \
  -d '{"device_mac":"00:11:22:33:44:01","payload":"temp=24.5"}'

# Non-whitelisted MAC (Expected: 403 Forbidden)
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:8000/iot/telemetry \
  -H 'Content-Type: application/json' \
  -d '{"device_mac":"AA:BB:CC:DD:EE:FF","payload":"temp=99.9"}'
```

---

## 🔄 Accounting Lifecycle Verification

To simulate the session accounting lifecycle (Start, Interim Update, Stop) and confirm database tracking:

**1. Send Session Start:**
```bash
echo "User-Name=zeynep,Acct-Status-Type=Start,Acct-Session-Id=session-999,NAS-IP-Address=127.0.0.1" \
  | docker exec -i nac_radius radclient -x localhost:1813 acct testing123
```
*Observe session `session-999` appears as "active" in the Redis session cache and dashboard.*

**2. Send Interim Update (Simulate traffic usage):**
```bash
echo "User-Name=zeynep,Acct-Status-Type=Interim-Update,Acct-Session-Id=session-999,NAS-IP-Address=127.0.0.1,Acct-Input-Octets=5000,Acct-Output-Octets=2500" \
  | docker exec -i nac_radius radclient -x localhost:1813 acct testing123
```

**3. Send Session Stop:**
```bash
echo "User-Name=zeynep,Acct-Status-Type=Stop,Acct-Session-Id=session-999,NAS-IP-Address=127.0.0.1,Acct-Session-Time=60,Acct-Input-Octets=15000,Acct-Output-Octets=8000" \
  | docker exec -i nac_radius radclient -x localhost:1813 acct testing123
```
*Observe that the session is removed from active sessions in Redis/Dashboard and written into the PostgreSQL `radacct` table.*

---

## 📖 Technical Report & Case Studies

A comprehensive academic and technical design report is available in the repository at:
*   [docs/NAC_System_Report.pdf](file:///home/baris/nac-system-freeradius/docs/NAC_System_Report.pdf) *(Teknik Tasarım ve Uygulama Raporu)*

This report covers:
1. **Detailed AAA Flow Mechanics:** Complete breakdown of the authentication, authorization (VLAN assignments), and accounting (Start/Interim/Stop database and cache updates) processes.
2. **Database Schema & Indexing:** Technical details of schema indexes (e.g., `idx_radcheck_username` and `idx_radacct_username`) for production scaling.
3. **Security Analysis:** Password hashing via Bcrypt, brute-force protection with Redis rate limiting, and MAC Authentication Bypass (MAB) logic.
4. **Real-World Application Case Studies:**
    *   **Denizli Textile Industry (IoT Safety):** Protecting legacy textile looms by assigning them to isolated VLANs via MAB, preventing lateral movement within the factory network.
    *   **BOTAŞ Pipeline Security (SCADA Isolation):** Securing critical valve sensors in SCADA networks, isolating sensor traffic from administrative/internet lines, and monitoring bandwidth via Interim-Updates.

---

## 📈 Cooja Simulation Details

For setting up the Contiki-NG serial connection, tunslip6 routing, and running the physical/simulated nodes, please refer to the detailed guide:
*   [simulation/README.md](file:///home/baris/nac-system-freeradius/simulation/README.md)

