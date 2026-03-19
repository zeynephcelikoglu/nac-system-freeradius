from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext

# Import local modules
from database import get_db
from models import RadCheck
from schemas import AuthRequest, AuthResponse

app = FastAPI(title="NAC Policy Engine")

# Password hashing configuration (bcrypt for security compliance)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.get("/")
def health_check():
    return {"status": "NAC API is running", "version": "1.0.0"}

@app.post("/auth", response_model=AuthResponse)
def authenticate_user(request: AuthRequest, db: Session = Depends(get_db)):
    # 1. Search for user in radcheck table
    user = db.query(RadCheck).filter(RadCheck.username == request.username).first()
    
    # 2. Return reject if user does not exist
    if not user:
        return {"status": "reject", "message": "User not found"}
    
    # Password verification
    # Note: Currently comparing plain text, will migrate to bcrypt hashing
    if request.password != user.value:
        return {"status": "reject", "message": "Invalid password"}

    # 3. Grant access if credentials are valid
    return {"status": "accept", "message": f"Welcome {request.username}"}