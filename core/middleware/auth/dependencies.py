from typing import List
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from core.database.connection.pgsql import get_session
from core.database.dao.users import UsersDAO, User
from core.security.jwt_handler import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Get the current user based on the provided JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    user_uuid: str | None = payload.get("sub")
    if user_uuid is None:
        raise credentials_exception

    user_dict = await UsersDAO().find_by_uuid(user_uuid)
    if user_dict is None:
        raise credentials_exception
    return user_dict

class RoleChecker:
    """Check if the user has one of the allowed roles."""
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("user_role") or "user"
        if user_role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required roles: {self.allowed_roles}"
            )
        return user
