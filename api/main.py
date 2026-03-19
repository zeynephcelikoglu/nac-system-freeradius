from fastapi import FastAPI, Request, Response
from contextlib import asynccontextmanager
import asyncpg
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database connection pool on startup
    app.state.db = await asyncpg.create_pool(os.environ["DATABASE_URL"])
    yield
    # Close database pool on shutdown
    await app.state.db.close()

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

@app.post("/accounting")
async def accounting(request: Request):
    # RADIUS Accounting endpoint (currently disabled for simplicity)
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
    # Placeholder for active sessions tracking
    return []