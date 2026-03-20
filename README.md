# Network Access Control (NAC) System

A containerized AAA (Authentication, Authorization, and Accounting) system built with FreeRADIUS, FastAPI, PostgreSQL, and Redis. Designed for dynamic network access control in enterprise and IoT environments.

---

## System Architecture & rlm_rest

The system follows a high-performance AAA architecture using FreeRADIUS 3.2 and a FastAPI Policy Engine:

```
[User/IoT Device]
              |
              | RADIUS Request (UDP 1812/1813)
              v
      [FreeRADIUS 3.2] ----------------> [PostgreSQL 18]
              |            (rlm_sql)     (radcheck: Auth Only)
              |
              | (rlm_rest)
              v
       [FastAPI Engine] <--------------> [Redis 8]
          (Port 8000)                  (Session Cache)
              |
              +------------------------> [PostgreSQL 18]
                                       (radacct, radgroupreply)
```

**rlm_rest Integration:** FreeRADIUS communicates with the FastAPI Policy Engine via the `rlm_rest` module. During the `authorize` phase, FreeRADIUS sends a `POST /authorize` request containing the User-Name and authentication context. FastAPI identifies the user, queries PostgreSQL for their assigned group and corresponding VLAN mappings, and returns RADIUS attributes (like `Tunnel-Private-Group-Id`) as a JSON response.

---

## Deployment & Environment

**1. Clone & Setup:**
```bash
git clone <repo_url> && cd nac-system-freeradius
cp .env.example .env
```

**2. Environment Configuration (.env.example):**
```bash
# --- Database Configuration ---
POSTGRES_USER=nac_admin
POSTGRES_PASSWORD=nac_pass
POSTGRES_DB=nac_db
# IMPORTANT: Use the Docker Compose service name 'nac_db', not 'localhost'
POSTGRES_HOST=nac_db        

# Use the credentials above to update the URL below:
# Format: postgresql://USER:PASSWORD@HOST:PORT/DB
DATABASE_URL=postgresql://nac_admin:nac_pass@nac_db:5432/nac_db

# --- Cache Configuration ---
# IMPORTANT: Use the Docker Compose service name 'nac_redis'
REDIS_HOST=nac_redis         
REDIS_PORT=6379

# --- Security & Radius ---
RADIUS_SECRET=testing123
API_SECRET_KEY=supersecretkey123
```

**3. Launch with Healthchecks:** All services include automated health probes.
```bash
docker-compose up -d --build
```

**4. Verification & Troubleshooting:**
```bash
# Check if all containers are running and healthy
docker ps

# Monitor real-time Policy Engine logic
docker logs -f nac_api

# Debug FreeRADIUS if it shows as 'unhealthy'
docker logs nac_radius
```

---

## Test Scenarios (Live Demo Guide)

### 1. Authentication Methods

**PAP Test:**
```bash
docker exec -it nac_radius radtest zeynep 123456 127.0.0.1 0 testing123
```

**MAB Test (Calling-Station-Id):**
```bash
echo "User-Name=00:11:22:33:44:55,User-Password=00:11:22:33:44:55,Calling-Station-Id=00:11:22:33:44:55" \
  | docker exec -i nac_radius radclient -x localhost:1812 auth testing123
```

### 2. Full Accounting Lifecycle (Start -> Interim -> Stop)

Simulate session tracking to verify database recording in `radacct`:

**Start Session:**
```bash
echo "User-Name=zeynep,Acct-Status-Type=Start,Acct-Session-Id=test-101,NAS-IP-Address=127.0.0.1" \
  | docker exec -i nac_radius radclient -x localhost:1813 acct testing123
```

**Interim Update (Traffic Data):**
```bash
echo "User-Name=zeynep,Acct-Status-Type=Interim-Update,Acct-Session-Id=test-101,NAS-IP-Address=127.0.0.1,Acct-Input-Octets=5000,Acct-Output-Octets=2500" \
  | docker exec -i nac_radius radclient -x localhost:1813 acct testing123
```

**Stop Session:**
```bash
echo "User-Name=zeynep,Acct-Status-Type=Stop,Acct-Session-Id=test-101,NAS-IP-Address=127.0.0.1,Acct-Session-Time=60,Acct-Input-Octets=15000,Acct-Output-Octets=8000" \
  | docker exec -i nac_radius radclient -x localhost:1813 acct testing123
```

---

## API Endpoints

| Endpoint          | Method | Description                              |
|-------------------|--------|------------------------------------------|
| `/auth`           | POST   | PAP/MAB authentication and result        |
| `/authorize`      | POST   | Returns dynamic VLAN & policy attributes |
| `/accounting`     | POST   | Saves session data to PostgreSQL         |
| `/users`          | GET    | Lists users and current status           |
| `/sessions/active`| GET    | Queries active sessions from Redis       |

**Verify Active Sessions:**
```bash
curl http://localhost:8000/sessions/active
```
