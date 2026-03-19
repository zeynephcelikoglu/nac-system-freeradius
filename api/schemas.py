from typing import Optional
from pydantic import BaseModel

# Request from RADIUS
class AuthRequest(BaseModel):
    username: str
    password: str

# Response to RADIUS
class AuthResponse(BaseModel):
    status: str
    message: str
    vlan: Optional[str] = None