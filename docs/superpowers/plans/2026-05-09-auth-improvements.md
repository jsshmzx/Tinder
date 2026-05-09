# Auth Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden and extend the auth system with rotating Refresh Tokens, a `/logout` endpoint, login tracking, and three code-quality fixes.

**Architecture:** A new `refresh_tokens` PostgreSQL table stores SHA-256-hashed tokens; every `/refresh` call revokes the old token and issues a new pair (rotation). Access tokens shrink to 1 hour; refresh tokens never expire until explicitly revoked.

**Tech Stack:** FastAPI, SQLAlchemy async ORM, PostgreSQL, `secrets` + `hashlib` (stdlib), python-jose, bcrypt.

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `tests/conftest.py` | Set `JWT_SECRET_KEY` before module imports |
| Modify | `core/security/jwt_handler.py` | Validate secret key at import; shorten TTL; add `generate_refresh_token` |
| Modify | `core/middleware/auth/dependencies.py` | Fix `tokenUrl`; move `import json` to top |
| Create | `core/database/migrations/SQL/add_refresh_tokens.sql` | New table DDL |
| Modify | `core/database/migrations/migration_history.py` | Register new migration |
| Create | `core/database/dao/refresh_tokens.py` | ORM model + DAO |
| Modify | `modules/api/v1/auth.py` | Update login; add `/refresh` and `/logout` |
| Modify | `modules/api/v1/users.py` | Optional refresh-token revocation in `change_password` |
| Modify | `tests/unit/test_api_v1_auth_router.py` | Update + add unit tests |
| Modify | `tests/integration/test_auth.py` | Update + add integration tests |
| Modify | `tests/integration/conftest.py` | Import `RefreshToken` model for table creation |

---

## Task 1: Test infrastructure + code hygiene

**Files:**
- Create: `tests/conftest.py`
- Modify: `core/security/jwt_handler.py`
- Modify: `core/middleware/auth/dependencies.py`

- [ ] **Step 1: Create root test conftest that sets JWT_SECRET_KEY**

`tests/conftest.py` must be the very first file pytest processes so `jwt_handler` sees the env var at import time.

```python
# tests/conftest.py
import os
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-key-do-not-use-in-prod")
```

- [ ] **Step 2: Fix `jwt_handler.py` — validate secret key, shorten TTL, add stdlib imports**

Replace the top section of `core/security/jwt_handler.py` (lines 1-10):

```python
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt, JWTError


SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY environment variable is not set. "
        "Set it to a long random string before starting the server."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour
```

- [ ] **Step 3: Fix `dependencies.py` — tokenUrl and import json**

In `core/middleware/auth/dependencies.py`, make two changes:

1. Line 1 — add `import json` to the stdlib imports block at the top of the file.

2. Line 13 — fix `tokenUrl`:
```python
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
```

3. Remove the two inline `import json` statements inside `get_current_user` (lines ~58 and ~69 in the original).

- [ ] **Step 4: Write the failing test for JWT secret validation**

Add to `tests/unit/test_api_v1_auth_router.py` (before the existing tests):

```python
import importlib
import os


def test_jwt_handler_raises_when_secret_key_missing(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    import core.security.jwt_handler as m
    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
        importlib.reload(m)
    # Restore so subsequent tests work
    monkeypatch.setenv("JWT_SECRET_KEY", "test-only-secret-key-do-not-use-in-prod")
    importlib.reload(m)
```

- [ ] **Step 5: Run test to verify it fails first**

```bash
pytest tests/unit/test_api_v1_auth_router.py::test_jwt_handler_raises_when_secret_key_missing -v
```

Expected: FAIL — `RuntimeError` not raised (the module still has a hardcoded fallback).

- [ ] **Step 6: Run all unit tests to confirm existing tests still pass**

```bash
pytest tests/unit/ --tb=short
```

Expected: All pass (the conftest.py sets the key before imports).

- [ ] **Step 7: Run the new test again — it should now pass**

```bash
pytest tests/unit/test_api_v1_auth_router.py::test_jwt_handler_raises_when_secret_key_missing -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add tests/conftest.py core/security/jwt_handler.py core/middleware/auth/dependencies.py tests/unit/test_api_v1_auth_router.py
git commit -m "fix: tokenUrl, JWT_SECRET_KEY validation, import json placement"
```

---

## Task 2: RefreshToken migration + DAO

**Files:**
- Create: `core/database/migrations/SQL/add_refresh_tokens.sql`
- Modify: `core/database/migrations/migration_history.py`
- Create: `core/database/dao/refresh_tokens.py`

- [ ] **Step 1: Write the SQL migration**

`core/database/migrations/SQL/add_refresh_tokens.sql`:

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

- [ ] **Step 2: Register migration**

In `core/database/migrations/migration_history.py`, append to the list:

```python
    "add_refresh_tokens.sql",
```

- [ ] **Step 3: Write the DAO**

`core/database/dao/refresh_tokens.py`:

```python
from datetime import datetime, timezone

from sqlalchemy import Integer, Text, select
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.pgsql import Base, get_session


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_uuid: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    created_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), server_default="now()"
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )


class RefreshTokensDAO:

    @staticmethod
    async def create(user_uuid: str, token_hash: str) -> None:
        async with get_session() as session:
            obj = RefreshToken(user_uuid=user_uuid, token_hash=token_hash)
            session.add(obj)
            await session.flush()

    @staticmethod
    async def find_active(token_hash: str) -> dict | None:
        async with get_session() as session:
            obj = (
                await session.scalars(
                    select(RefreshToken).where(
                        RefreshToken.token_hash == token_hash,
                        RefreshToken.revoked_at.is_(None),
                    )
                )
            ).first()
            if obj is None:
                return None
            return {"user_uuid": obj.user_uuid, "token_hash": obj.token_hash}

    @staticmethod
    async def revoke(token_hash: str) -> None:
        async with get_session() as session:
            obj = (
                await session.scalars(
                    select(RefreshToken).where(RefreshToken.token_hash == token_hash)
                )
            ).first()
            if obj:
                obj.revoked_at = datetime.now(timezone.utc)
                await session.flush()

    @staticmethod
    async def revoke_all_for_user(user_uuid: str) -> None:
        async with get_session() as session:
            objs = (
                await session.scalars(
                    select(RefreshToken).where(
                        RefreshToken.user_uuid == user_uuid,
                        RefreshToken.revoked_at.is_(None),
                    )
                )
            ).all()
            now = datetime.now(timezone.utc)
            for obj in objs:
                obj.revoked_at = now
            await session.flush()
```

- [ ] **Step 4: Update integration conftest to register the new model**

In `tests/integration/conftest.py`, add the import inside `db_engine` so `Base.metadata` includes the new table:

```python
    import core.database.dao.refresh_tokens  # noqa: F401
```

(Add it alongside the other DAO imports, e.g. after `import core.database.dao.users`)

- [ ] **Step 5: Commit**

```bash
git add core/database/migrations/SQL/add_refresh_tokens.sql \
        core/database/migrations/migration_history.py \
        core/database/dao/refresh_tokens.py \
        tests/integration/conftest.py
git commit -m "feat: add refresh_tokens table migration and DAO"
```

---

## Task 3: generate_refresh_token helper

**Files:**
- Modify: `core/security/jwt_handler.py`
- Modify: `tests/unit/test_api_v1_auth_router.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_api_v1_auth_router.py`:

```python
def test_generate_refresh_token_returns_distinct_plaintext_and_hash():
    from core.security.jwt_handler import generate_refresh_token
    import hashlib
    plaintext, token_hash = generate_refresh_token()
    assert len(plaintext) > 20
    assert token_hash == hashlib.sha256(plaintext.encode()).hexdigest()
    # Each call produces a unique token
    plaintext2, _ = generate_refresh_token()
    assert plaintext != plaintext2
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/unit/test_api_v1_auth_router.py::test_generate_refresh_token_returns_distinct_plaintext_and_hash -v
```

Expected: FAIL — `ImportError: cannot import name 'generate_refresh_token'`.

- [ ] **Step 3: Add generate_refresh_token to jwt_handler.py**

Append at the bottom of `core/security/jwt_handler.py`:

```python
def generate_refresh_token() -> tuple[str, str]:
    """Generate a cryptographically random refresh token.

    Returns (plaintext_token, sha256_hash). Store only the hash.
    """
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token, token_hash
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/unit/test_api_v1_auth_router.py::test_generate_refresh_token_returns_distinct_plaintext_and_hash -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/security/jwt_handler.py tests/unit/test_api_v1_auth_router.py
git commit -m "feat: add generate_refresh_token helper"
```

---

## Task 4: Update /auth/login (refresh token + login tracking)

**Files:**
- Modify: `modules/api/v1/auth.py`
- Modify: `tests/unit/test_api_v1_auth_router.py`
- Modify: `tests/integration/test_auth.py`

- [ ] **Step 1: Update the unit test for login success (it will fail after the change)**

Replace `test_login_success_returns_bearer_token` in `tests/unit/test_api_v1_auth_router.py`:

```python
def test_login_success_returns_bearer_token(client, monkeypatch):
    plain_password = "password123"
    hashed_password = get_password_hash(plain_password)
    user = SimpleNamespace(uuid="user-uuid-1", password=hashed_password)

    async def fake_find_by_username_or_email(session, login_identifier):
        assert login_identifier == "alice"
        return user

    async def fake_update(self, uuid, data):
        return {}

    async def fake_create_rt(user_uuid, token_hash):
        pass

    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(
        auth_v1.UsersDAO,
        "find_by_username_or_email",
        fake_find_by_username_or_email,
        raising=False,
    )
    monkeypatch.setattr(auth_v1.UsersDAO, "update", fake_update, raising=False)
    monkeypatch.setattr(auth_v1, "create_access_token", lambda subject: "mock-token-v1")
    monkeypatch.setattr(
        auth_v1, "generate_refresh_token", lambda: ("mock-refresh-token", "mock-hash")
    )
    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "create", fake_create_rt, raising=False)

    response = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": plain_password},
    )

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "mock-token-v1",
        "refresh_token": "mock-refresh-token",
        "token_type": "bearer",
    }
```

- [ ] **Step 2: Run the updated test to confirm it fails (endpoint not updated yet)**

```bash
pytest tests/unit/test_api_v1_auth_router.py::test_login_success_returns_bearer_token -v
```

Expected: FAIL — response body still missing `refresh_token`.

- [ ] **Step 3: Rewrite modules/api/v1/auth.py**

```python
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from core.database.connection.pgsql import get_session
from core.database.dao.users import UsersDAO
from core.database.dao.refresh_tokens import RefreshTokensDAO
from core.security.hash import verify_password
from core.security.jwt_handler import create_access_token, generate_refresh_token
from core.middleware.auth.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["Auth v1"])


@router.post("/login", response_model=dict[str, Any])
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """用户登录，返回 Access Token 和 Refresh Token。"""
    async with get_session() as session:
        user = await UsersDAO.find_by_username_or_email(session, form_data.username)
        if not user or not user.password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="用户名或密码错误",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not verify_password(form_data.password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="用户名或密码错误",
                headers={"WWW-Authenticate": "Bearer"},
            )

    user_uuid = str(user.uuid)
    access_token = create_access_token(subject=user_uuid)
    plaintext, token_hash = generate_refresh_token()

    await RefreshTokensDAO.create(user_uuid=user_uuid, token_hash=token_hash)
    await UsersDAO().update(user_uuid, {
        "last_login_at": datetime.now(timezone.utc),
        "last_login_ip": request.client.host if request.client else None,
    })

    return {
        "access_token": access_token,
        "refresh_token": plaintext,
        "token_type": "bearer",
    }


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


@router.get("/me", response_model=dict[str, Any])
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """获取当前登录用户信息。"""
    return {
        "uuid": current_user.get("uuid"),
        "real_name": current_user.get("real_name"),
        "role": current_user.get("user_role"),
    }


@router.post("/refresh", response_model=dict[str, Any])
async def refresh_tokens(body: RefreshRequest):
    """使用 Refresh Token 换取新的 Access Token 和 Refresh Token（轮转）。"""
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    record = await RefreshTokensDAO.find_active(token_hash)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效或已吊销的 Refresh Token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await RefreshTokensDAO.revoke(token_hash)

    user_uuid = record["user_uuid"]
    access_token = create_access_token(subject=user_uuid)
    plaintext, new_hash = generate_refresh_token()
    await RefreshTokensDAO.create(user_uuid=user_uuid, token_hash=new_hash)

    return {
        "access_token": access_token,
        "refresh_token": plaintext,
        "token_type": "bearer",
    }


@router.post("/logout", response_model=dict[str, Any])
async def logout(body: LogoutRequest, _: dict = Depends(get_current_user)):
    """登出当前设备，吊销 Refresh Token。Access Token 在有效期内自然失效。"""
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    await RefreshTokensDAO.revoke(token_hash)
    return {"message": "已登出"}
```

- [ ] **Step 4: Run login unit tests**

```bash
pytest tests/unit/test_api_v1_auth_router.py -v
```

Expected: All pass.

- [ ] **Step 5: Add integration test assertions for refresh_token and login tracking**

In `tests/integration/test_auth.py`, update `test_login_success_with_real_database`:

```python
def test_login_success_with_real_database(integration_client, test_user):
    response = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "testpassword123"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 0
    assert len(data["refresh_token"]) > 0
```

Also update `test_login_with_email` similarly (add `assert "refresh_token" in response.json()`).

- [ ] **Step 6: Run integration tests (requires DATABASE_URL + REDIS_URL)**

```bash
pytest tests/integration/test_auth.py --tb=short
```

Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add modules/api/v1/auth.py tests/unit/test_api_v1_auth_router.py tests/integration/test_auth.py
git commit -m "feat: update /auth/login — refresh token + login tracking"
```

---

## Task 5: POST /auth/refresh unit + integration tests

**Files:**
- Modify: `tests/unit/test_api_v1_auth_router.py`
- Modify: `tests/integration/test_auth.py`

The endpoint is already written in Task 4. This task adds its tests.

- [ ] **Step 1: Write failing unit tests for /auth/refresh**

Add to `tests/unit/test_api_v1_auth_router.py`:

```python
def test_refresh_token_success(client, monkeypatch):
    import hashlib
    plaintext = "valid-refresh-token"
    token_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    record = {"user_uuid": "user-uuid-1", "token_hash": token_hash}

    async def fake_find_active(h):
        return record if h == token_hash else None

    async def fake_revoke(h):
        pass

    async def fake_create(user_uuid, token_hash):
        pass

    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "find_active", fake_find_active, raising=False)
    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "revoke", fake_revoke, raising=False)
    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "create", fake_create, raising=False)
    monkeypatch.setattr(auth_v1, "create_access_token", lambda subject: "new-access-token")
    monkeypatch.setattr(
        auth_v1, "generate_refresh_token", lambda: ("new-refresh-token", "new-hash")
    )

    response = client.post("/api/v1/auth/refresh", json={"refresh_token": plaintext})

    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "new-access-token"
    assert data["refresh_token"] == "new-refresh-token"
    assert data["token_type"] == "bearer"


def test_refresh_token_returns_401_for_unknown_token(client, monkeypatch):
    async def fake_find_active(h):
        return None

    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "find_active", fake_find_active, raising=False)

    response = client.post("/api/v1/auth/refresh", json={"refresh_token": "bogus-token"})

    assert response.status_code == 401
    assert response.json()["detail"] == "无效或已吊销的 Refresh Token"
```

- [ ] **Step 2: Run unit tests**

```bash
pytest tests/unit/test_api_v1_auth_router.py::test_refresh_token_success tests/unit/test_api_v1_auth_router.py::test_refresh_token_returns_401_for_unknown_token -v
```

Expected: Both PASS.

- [ ] **Step 3: Write integration tests for /auth/refresh**

Add to `tests/integration/test_auth.py`:

```python
def test_refresh_token_issues_new_token_pair(integration_client, test_user):
    login = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "testpassword123"},
    )
    assert login.status_code == 200
    refresh_token = login.json()["refresh_token"]
    old_access_token = login.json()["access_token"]

    response = integration_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["access_token"] != old_access_token
    assert data["refresh_token"] != refresh_token


def test_refresh_token_revokes_old_token(integration_client, test_user):
    login = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "testpassword123"},
    )
    refresh_token = login.json()["refresh_token"]

    # First refresh succeeds
    r1 = integration_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert r1.status_code == 200

    # Reusing the same (now-revoked) token must fail
    r2 = integration_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert r2.status_code == 401


def test_refresh_token_fails_for_invalid_token(integration_client):
    response = integration_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": "completely-invalid-token"}
    )
    assert response.status_code == 401
```

- [ ] **Step 4: Run integration tests**

```bash
pytest tests/integration/test_auth.py -k "refresh" --tb=short
```

Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_api_v1_auth_router.py tests/integration/test_auth.py
git commit -m "test: add unit + integration tests for /auth/refresh"
```

---

## Task 6: POST /auth/logout tests

**Files:**
- Modify: `tests/unit/test_api_v1_auth_router.py`
- Modify: `tests/integration/test_auth.py`

- [ ] **Step 1: Write failing unit tests for /auth/logout**

Add to `tests/unit/test_api_v1_auth_router.py`:

```python
def test_logout_revokes_refresh_token(client, monkeypatch):
    import hashlib
    plaintext = "my-refresh-token"
    expected_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    revoked_hashes = []

    async def fake_revoke(h):
        revoked_hashes.append(h)

    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "revoke", fake_revoke, raising=False)
    client.app.dependency_overrides[auth_v1.get_current_user] = lambda: {"uuid": "u-1"}

    response = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": plaintext},
        headers={"Authorization": "Bearer token"},
    )
    client.app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {"message": "已登出"}
    assert expected_hash in revoked_hashes


def test_logout_requires_authentication(client):
    response = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": "any-token"},
    )
    assert response.status_code == 401
```

- [ ] **Step 2: Run unit tests**

```bash
pytest tests/unit/test_api_v1_auth_router.py::test_logout_revokes_refresh_token tests/unit/test_api_v1_auth_router.py::test_logout_requires_authentication -v
```

Expected: Both PASS.

- [ ] **Step 3: Write integration tests for /auth/logout**

Add to `tests/integration/test_auth.py`:

```python
def test_logout_revokes_refresh_token_integration(integration_client, test_user):
    login = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "testpassword123"},
    )
    tokens = login.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    logout = integration_client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout.status_code == 200
    assert logout.json() == {"message": "已登出"}

    # Refresh token must no longer work
    refresh_attempt = integration_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert refresh_attempt.status_code == 401


def test_logout_fails_without_access_token(integration_client):
    response = integration_client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": "any-token"},
    )
    assert response.status_code == 401
```

- [ ] **Step 4: Run integration tests**

```bash
pytest tests/integration/test_auth.py -k "logout" --tb=short
```

Expected: All pass.

- [ ] **Step 5: Run full test suite**

```bash
pytest tests/unit/ tests/integration/test_auth.py --tb=short
```

Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add tests/unit/test_api_v1_auth_router.py tests/integration/test_auth.py
git commit -m "test: add unit + integration tests for /auth/logout"
```

---

## Task 7: change-password refresh token revocation

**Files:**
- Modify: `modules/api/v1/users.py`
- Modify: `tests/unit/test_api_v1_users_router.py`
- Modify: `tests/integration/test_profile.py`

- [ ] **Step 1: Check existing change-password unit test**

```bash
grep -n "change_password\|password" tests/unit/test_api_v1_users_router.py | head -30
```

Note the existing test structure so you know what to update.

- [ ] **Step 2: Add the import and update ChangePasswordRequest in users.py**

At the top of `modules/api/v1/users.py`, after existing imports, add:

```python
from core.database.dao.refresh_tokens import RefreshTokensDAO
```

Update `ChangePasswordRequest` to add the optional field:

```python
class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1, description="当前密码")
    new_password: str = Field(
        ..., min_length=8, max_length=128, description="新密码（至少 8 个字符，首尾不能有空格）"
    )
    refresh_token: str | None = Field(
        None,
        description="当前设备的 Refresh Token（可选，提供后将自动吊销该设备的 Refresh Token）",
    )

    @field_validator("new_password")
    @classmethod
    def new_password_no_surrounding_spaces(cls, v: str) -> str:
        if v != v.strip():
            raise ValueError("新密码首尾不能包含空格")
        return v
```

- [ ] **Step 3: Add revocation at the end of change_password (after step 6, before return)**

In `change_password`, replace the final block (after `updated is None` check):

```python
    if updated is None:
        custom_log("ERROR", f"[ChangePassword] uuid={user_uuid} 用户不存在（update 返回 None）")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在",
        )

    if body.refresh_token is not None:
        import hashlib
        token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
        await RefreshTokensDAO.revoke(token_hash)

    custom_log("SUCCESS", f"[ChangePassword] uuid={user_uuid} 密码修改成功")
    return {"message": "密码修改成功"}
```

- [ ] **Step 4: Write the unit test for refresh token revocation on password change**

Add to `tests/unit/test_api_v1_users_router.py`:

```python
def test_change_password_revokes_refresh_token_when_provided(client, monkeypatch):
    import hashlib
    from modules.api.v1 import users as users_v1

    plaintext_rt = "my-current-refresh-token"
    expected_hash = hashlib.sha256(plaintext_rt.encode()).hexdigest()
    revoked = []

    current_user = {
        "uuid": "u-1",
        "password": get_password_hash("oldpassword1"),
        "current_status": "normal",
    }

    async def fake_update(self, uuid, data):
        return {"uuid": uuid, **data}

    async def fake_revoke(h):
        revoked.append(h)

    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)
    monkeypatch.setattr(users_v1.RefreshTokensDAO, "revoke", fake_revoke, raising=False)
    client.app.dependency_overrides[users_v1.get_current_user] = lambda: current_user

    response = client.patch(
        "/api/v1/users/me/password",
        json={
            "old_password": "oldpassword1",
            "new_password": "newpassword99",
            "refresh_token": plaintext_rt,
        },
    )
    client.app.dependency_overrides.clear()

    assert response.status_code == 200
    assert expected_hash in revoked


def test_change_password_succeeds_without_refresh_token(client, monkeypatch):
    from modules.api.v1 import users as users_v1

    current_user = {
        "uuid": "u-2",
        "password": get_password_hash("oldpassword1"),
        "current_status": "normal",
    }

    async def fake_update(self, uuid, data):
        return {"uuid": uuid, **data}

    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)
    client.app.dependency_overrides[users_v1.get_current_user] = lambda: current_user

    response = client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "oldpassword1", "new_password": "newpassword99"},
    )
    client.app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {"message": "密码修改成功"}
```

- [ ] **Step 5: Run unit tests**

```bash
pytest tests/unit/test_api_v1_users_router.py -v --tb=short
```

Expected: All pass (including the new tests and existing ones).

- [ ] **Step 6: Run integration test for change-password with refresh token**

Add to `tests/integration/test_profile.py` (append at end):

```python
def test_change_password_revokes_refresh_token(integration_client, test_user):
    login = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "testpassword123"},
    )
    tokens = login.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    change = integration_client.patch(
        "/api/v1/users/me/password",
        json={
            "old_password": "testpassword123",
            "new_password": "newtestpassword456",
            "refresh_token": refresh_token,
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert change.status_code == 200

    # Refresh token must be revoked
    refresh_attempt = integration_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert refresh_attempt.status_code == 401

    # Restore password so test_user fixture cleanup works
    login2 = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "newtestpassword456"},
    )
    new_access = login2.json()["access_token"]
    integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "newtestpassword456", "new_password": "testpassword123"},
        headers={"Authorization": f"Bearer {new_access}"},
    )
```

- [ ] **Step 7: Run full test suite**

```bash
pytest tests/ --tb=short
```

Expected: All pass.

- [ ] **Step 8: Final commit**

```bash
git add modules/api/v1/users.py \
        tests/unit/test_api_v1_users_router.py \
        tests/integration/test_profile.py
git commit -m "feat: revoke refresh token on password change"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|-----------------|------|
| Fix tokenUrl mismatch | Task 1 |
| JWT_SECRET_KEY validation | Task 1 |
| `import json` to top | Task 1 |
| `refresh_tokens` table | Task 2 |
| Rotating refresh token | Task 4 + 5 |
| 1-hour access token TTL | Task 1 (jwt_handler) |
| `/auth/refresh` endpoint | Task 4 (impl) + 5 (tests) |
| `/auth/logout` endpoint | Task 4 (impl) + 6 (tests) |
| Login updates last_login_at/ip | Task 4 |
| change-password revokes token | Task 7 |

**Placeholder scan:** None found.

**Type consistency:**
- `RefreshTokensDAO.create(user_uuid: str, token_hash: str)` — used consistently in Tasks 4, 7.
- `RefreshTokensDAO.find_active(token_hash: str) -> dict | None` — returns `{"user_uuid": ..., "token_hash": ...}`, `record["user_uuid"]` accessed in Task 4. Consistent.
- `RefreshTokensDAO.revoke(token_hash: str)` — called with hex digest throughout. Consistent.
- `generate_refresh_token() -> tuple[str, str]` — destructured as `plaintext, token_hash` throughout. Consistent.
