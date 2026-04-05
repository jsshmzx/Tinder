import os
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt, JWTError


SECRET_KEY = os.getenv("JWT_SECRET_KEY", "b3c9d1a2c5f7e8b6a3d4f1c9e1b5a1d4f7c8b2a3daaaf1")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

def create_access_token(subject: str | int, expires_delta: timedelta | None = None) -> str:
    """Create a JSON Web Token for the given subject."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> dict[str, Any] | None:
    """Decode a JSON Web Token."""
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_token
    except JWTError:
        return None

