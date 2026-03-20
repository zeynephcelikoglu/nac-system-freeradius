import os
import asyncpg
from redis import asyncio as aioredis
from fastapi import FastAPI, Request, Response
from contextlib import asynccontextmanager

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

@app.get("/")
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

@app.post("/auth")
async def auth(request: Request):
    """
    Step 2: Authentication
    Validates the user password against the database
    """
    body = await request.json()
    print("AUTH BODY:", body) # Log incoming request for debugging

    username = body.get("username") or body.get("User-Name")
    password = body.get("password") or body.get("User-Password")

    if not username or not password:
        return Response(status_code=401)

    # Verify Cleartext-Password from radcheck table
    async with app.state.db.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT value FROM radcheck
            WHERE username = $1 AND attribute = 'Cleartext-Password'
            LIMIT 1
            """,
            username,
        )

    # Check if user exists and password matches
    if not row or password != row["value"]:
        return Response(status_code=401)

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

@app.get("/sessions/active")
async def active_sessions():
    if not hasattr(app.state, "redis"):
        return []
    
    session_ids = await app.state.redis.smembers("active_sessions")
    results = []
    for s_id in session_ids:
        data = await app.state.redis.hgetall(f"session:{s_id.decode()}")
        results.append({"session_id": s_id.decode(), "user": data.get(b"username", b"").decode()})
    return results