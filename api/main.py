import os
import asyncpg
import bcrypt
import re
from redis import asyncio as aioredis
from fastapi import FastAPI, Request, Response, HTTPException, Query
from contextlib import asynccontextmanager
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field


class WhitelistRequest(BaseModel):
    mac_address: str = Field(..., description="MAC address in any common format")
    description: str = Field(default="", max_length=128)


class TelemetryRequest(BaseModel):
    device_mac: str = Field(..., description="Device MAC address")
    payload: str = Field(..., description="CoAP payload body")
    message_type: str = Field(default="coap", max_length=32)
    path: str = Field(default="/telemetry", max_length=128)
    source_ip: str = Field(default="", max_length=64)


async def write_access_log(
    username: str,
    mac_address: str,
    status: str,
    reason: str,
    source: str,
    session_id: str = "",
):
    try:
        async with app.state.db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO access_logs
                    (username, mac_address, status, reason, source, session_id)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                username,
                mac_address,
                status,
                reason,
                source,
                session_id,
            )
    except Exception as exc:
        print(f"ACCESS LOG ERROR: {exc}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize PostgreSQL connection pool
    app.state.db = await asyncpg.create_pool(os.environ["DATABASE_URL"])
    
    # Initialize Redis connection
    try:
        # Use Docker service name for container networking
        redis_host = os.environ.get("REDIS_HOST", "nac_redis")
        redis_port = os.environ.get("REDIS_PORT", "6379")
        
        app.state.redis = aioredis.from_url(
            f"redis://{redis_host}:{redis_port}",
            encoding="utf-8",
            decode_responses=True
        )
        # Verify connection
        await app.state.redis.ping()
        print(f"REDIS CONNECTED: {redis_host}:{redis_port}")
    except Exception as e:
        print(f"REDIS ERROR: {e}")
        app.state.redis = None
    
    yield
    
    # Graceful shutdown: close connections
    await app.state.db.close()
    if app.state.redis:
        await app.state.redis.close()

app = FastAPI(lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def index():
    return FileResponse("static/index.html")

@app.get("/health")
async def health():
    # Simple health check endpoint
    return {"status": "ok"}

@app.post("/authorize")
async def authorize(request: Request):
    """
    Step 1: Authorization
    Checks user group and assigns the correct VLAN ID
    """
    body = await request.json()
    username = body.get("User-Name") or body.get("username")

    if not username:
        return Response(status_code=401)

    # Fetch user's group from the database
    async with app.state.db.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT groupname FROM radusergroup WHERE username = $1 LIMIT 1",
            username,
        )

    # Map groups to specific VLAN IDs (Default to Guest VLAN 30)
    vlan_map = {"admin": "10", "employee": "20", "guest": "30"}
    vlan_id = vlan_map.get(row["groupname"] if row else None, "30")

    # Return standard RADIUS attributes for VLAN assignment
    return {
        "Tunnel-Type": "13",
        "Tunnel-Medium-Type": "6",
        "Tunnel-Private-Group-Id": vlan_id,
    }

def is_mac_address(value: str) -> bool:
    # Validate MAC address format (00:11:22:33:44:55 or 001122334455)
    clean = str(value).upper().replace(":", "").replace("-", "")
    return bool(re.fullmatch(r"[0-9A-F]{12}", clean))

def normalize_mac(value: str) -> str:
    # Normalize MAC address to 00:11:22:33:44:55 format
    clean = str(value).upper().replace(":", "").replace("-", "")
    return ":".join(clean[i:i+2] for i in range(0, 12, 2))

@app.post("/auth")
async def auth(request: Request):
    body = await request.json()
    username = body.get("username") or body.get("User-Name")
    password = body.get("password") or body.get("User-Password")
    session_id = body.get("Acct-Session-Id", "")
    auth_source = "mab" if is_mac_address(str(username)) or is_mac_address(str(password)) else "pap"

    print(
        f"AUTH INCOMING: user={username!r} source={auth_source} "
        f"is_user_mac={is_mac_address(str(username)) if username else False} "
        f"is_pass_mac={is_mac_address(str(password)) if password else False}"
    )

    if not username or not password:
        await write_access_log(str(username or ""), "", "REJECT", "missing_credentials", auth_source, str(session_id or ""))
        return Response(status_code=401)

    # Handle MAC Authentication Bypass (MAB) for IoT devices
    if is_mac_address(str(username)) or is_mac_address(str(password)):
        candidate_mac = str(username) if is_mac_address(str(username)) else str(password)
        mac = normalize_mac(candidate_mac)
        print(f"MAB REQUEST: {mac}")
        async with app.state.db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id FROM mac_whitelist WHERE mac_address = $1 AND enabled = TRUE",
                mac,
            )
        if row:
            print(f"MAB ACCEPT: {mac}")
            await write_access_log(str(username), mac, "ACCEPT", "mac_whitelisted", "mab", str(session_id or ""))
            return Response(status_code=200)
        print(f"MAB REJECT: {mac} not in whitelist")
        await write_access_log(str(username), mac, "REJECT", "mac_not_whitelisted", "mab", str(session_id or ""))
        return Response(status_code=401)

    # Apply rate-limiting to prevent brute-force attacks
    redis = getattr(app.state, "redis", None)
    rate_key = f"auth_fail:{username}"
    if redis:
        fail_count = await redis.get(rate_key)
        if fail_count and int(fail_count) >= 5:
            print(f"RATE LIMIT: {username} blocked for 5 minutes")
            return Response(status_code=429) 

    # Verify Cleartext-Password from radcheck table
    async with app.state.db.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT attribute, value FROM radcheck
            WHERE username = $1 
            AND attribute IN ('Bcrypt-Password', 'Cleartext-Password')
            LIMIT 1
            """,
            username,
        )

    if not row or not row["value"]:
        await write_access_log(str(username), "", "REJECT", "user_not_found", "pap", str(session_id or ""))
        return Response(status_code=401)

    verified = False
    if row["attribute"] == "Bcrypt-Password":
        verified = bcrypt.checkpw(password.encode("utf-8"), row["value"].encode("utf-8"))
    else:
        verified = (password == row["value"])

    # Handle failed authentication and increment rate limit counter
    if not verified:
        if redis:
            await redis.incr(rate_key)
            await redis.expire(rate_key, 300) # Block for 5 minutes
            count = await redis.get(rate_key)
            print(f"AUTH FAIL: {username} ({count}/5)")
        await write_access_log(str(username), "", "REJECT", "invalid_password", "pap", str(session_id or ""))
        return Response(status_code=401)

    # Reset rate limit counter on successful login
    if redis:
        await redis.delete(rate_key)
    print(f"AUTH OK: {username}")
    await write_access_log(str(username), "", "ACCEPT", "password_verified", "pap", str(session_id or ""))

    return Response(status_code=200)

def extract(field):
    """
    Flatten nested RADIUS attributes from FreeRADIUS rlm_rest JSON format.
    Handles dictionary wraps, lists, and direct string/int values.
    """
    if isinstance(field, dict):
        val = field.get("value", field.get("Value", ""))
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val)
    if isinstance(field, list):
        return str(field[0]) if field else ""
    return str(field) if field is not None else ""

@app.post("/accounting")
async def accounting(request: Request):
    try:
        # Parse incoming JSON payload
        body = await request.json()
        print("ACCOUNTING RAW:", body)
    except Exception as e:
        print(f"ACCOUNTING JSON ERROR: {e}")
        return Response(status_code=204)

    try:
        # Sanitize and flatten RADIUS attributes
        raw_status   = extract(body.get("Acct-Status-Type", ""))
        session_id   = extract(body.get("Acct-Session-Id", ""))
        username     = extract(body.get("User-Name", ""))
        nas_ip       = extract(body.get("NAS-IP-Address", "127.0.0.1"))
        calling_id   = extract(body.get("Calling-Station-Id", ""))
        session_time = int(extract(body.get("Acct-Session-Time", "0")) or 0)
        input_oct    = int(extract(body.get("Acct-Input-Octets", "0")) or 0)
        output_oct   = int(extract(body.get("Acct-Output-Octets", "0")) or 0)

        # Map RADIUS status codes to internal state
        STATUS_MAP = {
            "1": "Start",           "Start": "Start",
            "2": "Stop",            "Stop":  "Stop",
            "3": "Interim-Update",  "Interim-Update": "Interim-Update",
        }
        status_type = STATUS_MAP.get(raw_status, "")

        print(f"ACCOUNTING CLEAN: status={status_type!r} session={session_id!r} "
              f"user={username!r} nas={nas_ip!r}")

        if not session_id or not status_type:
            print(f"ACCOUNTING SKIP: missing session_id or status")
            return Response(status_code=204)

        # Database operations (PostgreSQL)
        async with app.state.db.acquire() as conn:

            if status_type == "Start":
                result = await conn.execute(
                    """
                    INSERT INTO radacct
                        (acctsessionid, username, nasipaddress,
                         acctstarttime, callingstationid, acctstatustype)
                    VALUES ($1, $2, $3, NOW(), $4, 'Start')
                    """,
                    session_id, username, nas_ip, calling_id,
                )
                print(f"ACCOUNTING DB INSERT: {result}")

            elif status_type == "Stop":
                result = await conn.execute(
                    """
                    UPDATE radacct SET
                        acctstoptime     = NOW(),
                        acctsessiontime  = $1,
                        acctinputoctets  = $2,
                        acctoutputoctets = $3,
                        acctstatustype   = 'Stop'
                    WHERE acctsessionid  = $4
                    """,
                    session_time, input_oct, output_oct, session_id,
                )
                print(f"ACCOUNTING DB UPDATE Stop: {result}")

            elif status_type == "Interim-Update":
                result = await conn.execute(
                    """
                    UPDATE radacct SET
                        acctupdatetime   = NOW(),
                        acctinputoctets  = $1,
                        acctoutputoctets = $2,
                        acctstatustype   = 'Interim-Update'
                    WHERE acctsessionid  = $3
                    """,
                    input_oct, output_oct, session_id,
                )
                print(f"ACCOUNTING DB UPDATE Interim: {result}")

        # Cache operations (Redis)
        redis = getattr(app.state, "redis", None)
        if redis:
            try:
                if status_type == "Start":
                    await redis.hset(f"session:{session_id}", mapping={
                        "username": username,
                        "nas_ip":   nas_ip,
                        "status":   "active",
                    })
                    await redis.sadd("active_sessions", session_id)
                    print(f"ACCOUNTING REDIS SET: session:{session_id}")

                elif status_type == "Stop":
                    await redis.delete(f"session:{session_id}")
                    await redis.srem("active_sessions", session_id)
                    print(f"ACCOUNTING REDIS DEL: session:{session_id}")

                elif status_type == "Interim-Update":
                    await redis.hset(f"session:{session_id}", mapping={
                        "input_octets":  str(input_oct),
                        "output_octets": str(output_oct),
                    })
                    print(f"ACCOUNTING REDIS UPDATE: session:{session_id}")

            except Exception as e:
                print(f"ACCOUNTING REDIS ERROR: {e}")
        else:
            print("ACCOUNTING REDIS SKIP: no connection")

        print(f"ACCOUNTING DONE: {status_type} / {session_id}")

    except Exception as e:
        print(f"ACCOUNTING CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()

    return Response(status_code=204)

@app.get("/users")
async def list_users():
    # Fetch all users and their groups for the dashboard
    async with app.state.db.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT r.username, g.groupname
            FROM radcheck r
            LEFT JOIN radusergroup g ON r.username = g.username
            ORDER BY r.username
            """
        )
    return [{"username": r["username"], "group": r["groupname"]} for r in rows]


@app.get("/whitelist")
async def list_whitelist():
    async with app.state.db.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT mac_address, description, enabled, created_at
            FROM mac_whitelist
            ORDER BY created_at DESC
            """
        )
    return [
        {
            "mac_address": row["mac_address"],
            "description": row["description"],
            "enabled": row["enabled"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        }
        for row in rows
    ]


@app.post("/whitelist", status_code=201)
async def add_whitelist_device(item: WhitelistRequest):
    if not is_mac_address(item.mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    mac = normalize_mac(item.mac_address)
    async with app.state.db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO mac_whitelist (mac_address, description, enabled)
            VALUES ($1, $2, TRUE)
            ON CONFLICT (mac_address)
            DO UPDATE SET
                description = EXCLUDED.description,
                enabled = TRUE
            """,
            mac,
            item.description,
        )
    return {"message": "device_whitelisted", "mac_address": mac}


@app.delete("/whitelist/{mac_address}")
async def disable_whitelist_device(mac_address: str):
    if not is_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    mac = normalize_mac(mac_address)
    async with app.state.db.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE mac_whitelist
            SET enabled = FALSE
            WHERE mac_address = $1
            """,
            mac,
        )

    if result.endswith("0"):
        raise HTTPException(status_code=404, detail="MAC not found")
    return {"message": "device_disabled", "mac_address": mac}


@app.get("/logs/access")
async def access_logs(limit: int = Query(default=50, ge=1, le=500)):
    async with app.state.db.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT created_at, username, mac_address, status, reason, source, session_id
            FROM access_logs
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )

    return [
        {
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "username": row["username"],
            "mac_address": row["mac_address"],
            "status": row["status"],
            "reason": row["reason"],
            "source": row["source"],
            "session_id": row["session_id"],
        }
        for row in rows
    ]


@app.post("/iot/telemetry", status_code=202)
async def ingest_iot_telemetry(data: TelemetryRequest):
    if not is_mac_address(data.device_mac):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    mac = normalize_mac(data.device_mac)
    async with app.state.db.acquire() as conn:
        device = await conn.fetchrow(
            "SELECT id FROM mac_whitelist WHERE mac_address = $1 AND enabled = TRUE",
            mac,
        )

        if not device:
            await write_access_log(mac, mac, "REJECT", "telemetry_from_untrusted_device", "coap")
            raise HTTPException(status_code=403, detail="Device not whitelisted")

        await conn.execute(
            """
            INSERT INTO iot_telemetry (device_mac, payload, message_type, path, source_ip)
            VALUES ($1, $2, $3, $4, $5)
            """,
            mac,
            data.payload,
            data.message_type,
            data.path,
            data.source_ip,
        )

    return {"message": "telemetry_accepted", "device_mac": mac}


@app.get("/iot/telemetry")
async def get_iot_telemetry(limit: int = Query(default=50, ge=1, le=500)):
    async with app.state.db.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT created_at, device_mac, payload, message_type, path, source_ip
            FROM iot_telemetry
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )

    return [
        {
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "device_mac": row["device_mac"],
            "payload": row["payload"],
            "message_type": row["message_type"],
            "path": row["path"],
            "source_ip": row["source_ip"],
        }
        for row in rows
    ]

@app.get("/sessions/active")
async def active_sessions():
    # Check if Redis connection exists
    redis = getattr(app.state, "redis", None)
    if not redis:
        return []
    
    # Retrieve all active session IDs from Redis set
    session_ids = await app.state.redis.smembers("active_sessions")
    results = []
    for s_id in session_ids:
        # Fetch detailed session data from Redis hash
        data = await redis.hgetall(f"session:{s_id}")
        results.append({
            "session_id": s_id,
            "username":   data.get("username", ""),
            "nas_ip":     data.get("nas_ip", ""),
            "status":     data.get("status", ""),
        })

    # Return the list of active sessions as JSON
    return results