import redis
import json
from typing import Optional, Dict
from fastapi import FastAPI, Depends, HTTPException, status, Body
from sqlalchemy.orm import Session
from passlib.context import CryptContext

# Import local modules
from database import get_db
from models import RadCheck
from schemas import AuthRequest, AuthResponse

app = FastAPI(title="NAC Policy Engine")

# Redis connection setup
redis_client = redis.Redis(host="nac_redis", port=6379, db=0, decode_responses=True)

# Password hashing configuration for secure credential verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.get("/")
def health_check():
    """Simple health check endpoint to verify API status."""
    return {"status": "NAC API is running", "version": "1.0.0"}

@app.post("/auth")
def authenticate_user(request: AuthRequest, db: Session = Depends(get_db)):
    """
    Handles RADIUS Access-Request.
    Verifies user credentials against PostgreSQL and returns dynamic VLAN policy.
    """
    # Query user from the radcheck table in PostgreSQL
    user = db.query(RadCheck).filter(RadCheck.username == request.username).first()

    # Verify user existence and password match
    if not user or request.password != user.value:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Return standard RADIUS attributes for dynamic VLAN assignment
    return {
        "Tunnel-Type": "VLAN",
        "Tunnel-Medium-Type": "IEEE-802",
        "Tunnel-Private-Group-Id": "10" 
    }

@app.post("/accounting")
async def process_accounting(data: Dict = Body(...)):
    """
    Handles RADIUS Accounting-Request (Start/Stop).
    Normalizes incoming data and manages real-time session state in Redis.
    """
    # Normalize keys to lowercase to handle different RADIUS attribute formats
    clean_data = {str(k).lower(): v for k, v in data.items()}
    print(f"DEBUG Temizlenmiş Veri: {clean_data}")

    # Extract required attributes from normalized data
    username = clean_data.get("user-name") or clean_data.get("username")
    status_type = str(clean_data.get("acct-status-type") or clean_data.get("status_type") or "").lower()
    session_id = clean_data.get("acct-session-id") or clean_data.get("session_id")

    # Extract username and handle potential dictionary-like structures from RADIUS
    raw_username = clean_data.get("user-name") or clean_data.get("username")
    
    # If the username comes as a dict/list extract the string
    if isinstance(raw_username, dict):
        username = raw_username.get("value", [None])[0]
    elif isinstance(raw_username, list):
        username = raw_username[0]
    else:
        username = raw_username

    if username:
        # Normalize username to string and remove any unwanted characters
        username = str(username).strip()
        redis_key = f"session:{username}"
        # If user session starts, store it in Redis
        if "start" in status_type:
            redis_client.set(redis_key, str(session_id))
            print(f"DEBUG: {username} Redis'e YAZILDI.")
        # If user session stops, remove it from Redis
        elif "stop" in status_type:
            redis_client.delete(redis_key)
            print(f"DEBUG: {username} Redis'ten SİLİNDİ.")
    
    return {"status": "success"}

@app.get("/sessions/active")
async def get_active_sessions():
    """
    Retrieves all active network sessions from Redis.
    Used for real-time monitoring of connected users.
    """
    # Fetch all keys matching the session pattern
    keys = redis_client.keys("session:*")
    # Extract only the username part from the Redis keys
    active_users = [k.replace("session:", "") for k in keys]
    return {
        "count": len(active_users),
        "active_users": active_users
    }