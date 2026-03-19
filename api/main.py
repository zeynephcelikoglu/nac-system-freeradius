import redis
import json
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext

# Import local modules
from database import get_db
from models import RadCheck
from schemas import AuthRequest, AuthResponse

app = FastAPI(title="NAC Policy Engine")

# Redis connection setup
redis_client = redis.Redis(host="redis", port=6379, db=0, decode_responses=True)

# Password hashing configuration (bcrypt for security compliance)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.get("/")
def health_check():
    return {"status": "NAC API is running", "version": "1.0.0"}

@app.post("/auth", response_model=AuthResponse)
def authenticate_user(request: AuthRequest, db: Session = Depends(get_db)):
    # Redis cache check
    cache_key = f"auth:{request.username}:{request.password}"
    cached_result = redis_client.get(cache_key)

    if cached_result:
        return json.loads(cached_result)

    # 1. Search for user in radcheck table
    user = db.query(RadCheck).filter(RadCheck.username == request.username).first()
    
    # 2. Return reject if user does not exist
    if not user:
        return {"status": "reject", "message": "User not found", "vlan": None}
    
    # Password verification
    if request.password != user.value:
        return {"status": "reject", "message": "Invalid password", "vlan": None}

    # 3. Authorization: Grant access and assign dynamic VLAN policy
    assigned_vlan = "10"
    result = {
        "status": "accept", 
        "message": f"Welcome {request.username}",
        "vlan": assigned_vlan
    }

    redis_client.setex(cache_key, 60, json.dumps(result))

    return result
    