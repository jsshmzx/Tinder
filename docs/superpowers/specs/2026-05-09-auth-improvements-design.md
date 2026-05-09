# Auth API Improvements Design

**Date:** 2026-05-09  
**Status:** Approved

## Overview

Five targeted improvements to the existing auth system:

1. Fix `tokenUrl` mismatch in Swagger UI
2. Fail fast on missing `JWT_SECRET_KEY`
3. Move `import json` to module top level
4. Rotating Refresh Token system with PostgreSQL persistence
5. Record `last_login_at` / `last_login_ip` on every login

---

## Section 1: Quick Fixes

### 1.1 `tokenUrl` correction

**File:** `core/middleware/auth/dependencies.py:13`

Change:
```python
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
```
To:
```python
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
```

The router is mounted at `/api/v1` in `server.py`, so the current value points to a non-existent URL, breaking the Swagger UI Authorize button.

### 1.2 JWT secret key validation

**File:** `core/security/jwt_handler.py`

Remove the hardcoded fallback. Raise `RuntimeError` at module load time if `JWT_SECRET_KEY` is not set:

```python
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable is not set")
```

This prevents silent use of a weak key in production.

### 1.3 `import json` at module level

**File:** `core/middleware/auth/dependencies.py`

Move both inline `import json` statements (lines 58 and 69) to the top of the file.

---

## Section 2: Refresh Token System

### 2.1 Database migration

New file: `core/database/migrations/SQL/add_refresh_tokens.sql`

```sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         SERIAL PRIMARY KEY,
    user_uuid  TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    revoked_at TIMESTAMP WITH TIME ZONE NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_uuid ON refresh_tokens(user_uuid);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
```

Append `"add_refresh_tokens.sql"` to the ordered list in `core/database/migrations/migration_history.py`.

### 2.2 DAO

New file: `core/database/dao/refresh_tokens.py`

ORM model `RefreshToken` mapped to `refresh_tokens` table.

`RefreshTokensDAO` methods:
- `create(user_uuid: str, token_hash: str) -> dict` — insert new row
- `find_active(token_hash: str) -> dict | None` — find row where `revoked_at IS NULL` and `token_hash` matches
- `revoke(token_hash: str) -> None` — set `revoked_at = now()` for the matching row
- `revoke_all_for_user(user_uuid: str) -> None` — bulk revoke all active tokens for a user (password reset / admin action)

### 2.3 Token generation helper

**File:** `core/security/jwt_handler.py`

Add a function to generate a Refresh Token (opaque random string):

```python
import secrets, hashlib

def generate_refresh_token() -> tuple[str, str]:
    """Returns (plaintext_token, sha256_hash)."""
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token, token_hash
```

### 2.4 Updated `POST /auth/login`

**File:** `modules/api/v1/auth.py`

After password verification:
1. Generate refresh token via `generate_refresh_token()`
2. Insert `token_hash` into `refresh_tokens` via `RefreshTokensDAO.create()`
3. Return both tokens:

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "bearer"
}
```

Access Token TTL: 1 hour (`ACCESS_TOKEN_EXPIRE_MINUTES = 60`).

### 2.5 New `POST /auth/refresh`

**File:** `modules/api/v1/auth.py`

Request body: `{ "refresh_token": "string" }`

Flow:
1. SHA-256 hash the incoming token
2. `RefreshTokensDAO.find_active(hash)` — 401 if not found or already revoked
3. `RefreshTokensDAO.revoke(old_hash)` — immediately invalidate old token
4. `generate_refresh_token()` → insert new token into DB
5. `create_access_token(user_uuid)` — new Access Token
6. Return `{ "access_token": "...", "refresh_token": "...", "token_type": "bearer" }`

No authentication dependency required (the refresh token itself is the credential).

### 2.6 New `POST /auth/logout`

**File:** `modules/api/v1/auth.py`

Requires Bearer auth (`Depends(get_current_user)`).  
Request body: `{ "refresh_token": "string" }`

Flow:
1. SHA-256 hash the incoming token
2. `RefreshTokensDAO.revoke(hash)` — mark revoked
3. Return `{ "message": "已登出" }`

The Access Token expires naturally after 1 hour.

### 2.7 `change-password` integration

**File:** `modules/api/v1/users.py`

After a successful password change, the client should pass its current `refresh_token` in the request body. The endpoint calls `RefreshTokensDAO.revoke(hash)` to invalidate the current device's session, forcing re-login.

If the client does not provide a refresh token, the change still succeeds — only the active session revocation is skipped.

---

## Section 3: Login Tracking

**File:** `modules/api/v1/auth.py`

The `login` endpoint signature adds `request: Request` parameter.

After password verification, before returning the token response, call:

```python
await UsersDAO().update(str(user.uuid), {
    "last_login_at": datetime.now(timezone.utc),
    "last_login_ip": request.client.host if request.client else None,
})
```

No schema changes required — both columns already exist on the `users` table.

---

## Files Changed / Created

| Action | Path |
|--------|------|
| Edit | `core/middleware/auth/dependencies.py` |
| Edit | `core/security/jwt_handler.py` |
| Edit | `modules/api/v1/auth.py` |
| Edit | `modules/api/v1/users.py` |
| Edit | `core/database/migrations/migration_history.py` |
| Create | `core/database/migrations/SQL/add_refresh_tokens.sql` |
| Create | `core/database/dao/refresh_tokens.py` |

---

## Token Lifecycle Summary

```
Login  →  access_token (1h) + refresh_token (∞, until revoked)
Refresh →  old refresh_token revoked, new pair issued
Logout  →  refresh_token revoked, access_token expires naturally (≤1h)
change-password → refresh_token revoked (if provided), re-login required
```
