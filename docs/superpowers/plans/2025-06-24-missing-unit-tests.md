# Missing Unit Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ~37 missing unit tests across auth, users, and admin router test files to cover untested branches and endpoints.

**Architecture:** Each test is a pure mocked unit test following the established patterns: `monkeypatch` to replace DAO/Redis methods, `TestClient` for HTTP invocation, `SimpleNamespace` for mock Redis clients, and `_mock_get_session()` for DB session context.

**Tech Stack:** Python 3, FastAPI TestClient, pytest, monkeypatch, SimpleNamespace

**Constraints:** All tests must work without a real database or Redis. No integration tests. No external dependencies.

## Global Constraints

- All tests must pass with `pytest tests/unit/ --tb=short` (no DB/Redis required)
- Follow existing file patterns: same fixture structure, same mock style, same import order
- Use `monkeypatch.setattr()` to replace DAO methods and Redis interactions
- Use `SimpleNamespace` for mock Redis clients
- Use `_mock_get_session()` context manager for DB session mocking
- Use `FastAPI()` + `TestClient` with `dependency_overrides` for auth mock
- For `get_temp_user` mock, use `dependency_overrides` directly (not monkeypatch)
- `hash_password` in `core.security.password` is a pass-through; `verify_password` uses `hmac.compare_digest`
- Passwords arrive as 64-char SHA256 hex strings (double-hashed client-side)
- `SUPER_PASSWORD` must be available in `settings.SUPER_PASSWORD` for admin tests
- `JWT_SECRET_KEY` set to `"test-only-secret-key-do-not-use-in-prod"` in `tests/conftest.py`
- Never use `print()` — existing tests use it for debug labels, which is acceptable

---

### Task 1: Auth router — login/refresh missing branches

**Files:**
- Modify: `tests/unit/test_api_v1_auth_router.py` (append new tests before the last line)

**Interfaces:**
- Consumes: existing mock helpers `_sha256_hex`, `_mock_get_session`, `client` fixture
- Produces: 8 new test functions

- [ ] **Step 1: Write `test_login_returns_403_when_disabled`**

```python
def test_login_returns_403_when_disabled(client, monkeypatch):
    """disabled 状态登录返回 403。"""
    plain_password = "password123"
    hex_password = _sha256_hex(plain_password)
    hashed_password = _hash_password(hex_password)
    user = SimpleNamespace(uuid="user-uuid-disabled", password=hashed_password, current_status="disabled")

    async def fake_find_by_username_or_email(session, login_identifier):
        return user

    # Mock _login_redis_incr to skip rate limiting
    monkeypatch.setattr(auth_v1, "_login_redis_incr", lambda key, ttl: 0)
    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(auth_v1.UsersDAO, "find_by_username_or_email", fake_find_by_username_or_email, raising=False)
    monkeypatch.setattr(auth_v1, "verify_password", lambda p, s: True)

    response = client.post(
        "/auth/login",
        json={"username": "disabled_user", "password": hex_password},
    )

    assert response.status_code == 403
    assert "账号已被禁用" in response.json()["detail"]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/unit/test_api_v1_auth_router.py::test_login_returns_403_when_disabled -v`
Expected: FAIL (function not defined yet)

- [ ] **Step 3: Verify it passes (test is the implementation — add test, run again)**

Run: `pytest tests/unit/test_api_v1_auth_router.py::test_login_returns_403_when_disabled -v`
Expected: PASS

- [ ] **Step 4: Write `test_login_returns_403_when_banned`**

```python
def test_login_returns_403_when_banned(client, monkeypatch):
    """banned 状态登录返回 403。"""
    plain_password = "password123"
    hex_password = _sha256_hex(plain_password)
    hashed_password = _hash_password(hex_password)
    user = SimpleNamespace(uuid="user-uuid-banned", password=hashed_password, current_status="banned")

    async def fake_find_by_username_or_email(session, login_identifier):
        return user

    monkeypatch.setattr(auth_v1, "_login_redis_incr", lambda key, ttl: 0)
    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(auth_v1.UsersDAO, "find_by_username_or_email", fake_find_by_username_or_email, raising=False)
    monkeypatch.setattr(auth_v1, "verify_password", lambda p, s: True)

    response = client.post(
        "/auth/login",
        json={"username": "banned_user", "password": hex_password},
    )

    assert response.status_code == 403
    assert "账号已被禁用" in response.json()["detail"]
```

- [ ] **Step 5: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_auth_router.py::test_login_returns_403_when_banned -v`
Expected: PASS

- [ ] **Step 6: Write `test_login_returns_429_when_ip_rate_limited`**

```python
def test_login_returns_429_when_ip_rate_limited(client, monkeypatch):
    """IP 登录速率超过限制时返回 429。"""
    from core.config import settings

    # Mock _login_redis_incr to return above-threshold for IP key
    def fake_incr(key, ttl):
        if "ip:" in key:
            return settings.LOGIN_MAX_ATTEMPTS_PER_IP_PER_MINUTE + 1
        return 0

    monkeypatch.setattr(auth_v1, "_login_redis_incr", fake_incr)

    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": _sha256_hex("whatever")},
    )

    assert response.status_code == 429
    assert "过于频繁" in response.json()["detail"]
```

- [ ] **Step 7: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_auth_router.py::test_login_returns_429_when_ip_rate_limited -v`
Expected: PASS

- [ ] **Step 8: Write `test_login_returns_429_when_username_rate_limited`**

```python
def test_login_returns_429_when_username_rate_limited(client, monkeypatch):
    """username 登录速率超过限制时返回 429。"""
    from core.config import settings

    def fake_incr(key, ttl):
        if "un:" in key:
            return settings.LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_MINUTE + 1
        return 0

    monkeypatch.setattr(auth_v1, "_login_redis_incr", fake_incr)

    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": _sha256_hex("whatever")},
    )

    assert response.status_code == 429
    assert "过于频繁" in response.json()["detail"]
```

- [ ] **Step 9: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_auth_router.py::test_login_returns_429_when_username_rate_limited -v`
Expected: PASS

- [ ] **Step 10: Write `test_refresh_returns_401_when_user_not_found`**

```python
def test_refresh_returns_401_when_user_not_found(client, monkeypatch):
    """refresh token 对应的用户不存在时返回 401。"""
    import hashlib
    plaintext = "some-token"
    token_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    record = {"user_uuid": "nonexistent-uuid", "token_hash": token_hash}

    async def fake_find_active(h):
        return record if h == token_hash else None

    async def fake_find_by_uuid(self, uuid):
        return None  # 用户不存在

    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "find_active", fake_find_active, raising=False)
    monkeypatch.setattr(auth_v1.UsersDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    response = client.post("/auth/refresh", json={"refresh_token": plaintext})

    assert response.status_code == 401
    assert "用户不存在" in response.json()["detail"]
```

- [ ] **Step 11: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_auth_router.py::test_refresh_returns_401_when_user_not_found -v`
Expected: PASS

- [ ] **Step 12: Write `test_refresh_returns_401_when_user_disabled`**

```python
def test_refresh_returns_401_when_user_disabled(client, monkeypatch):
    """refresh 时用户被禁用返回 401。"""
    import hashlib
    plaintext = "disabled-user-token"
    token_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    record = {"user_uuid": "disabled-uuid", "token_hash": token_hash}

    async def fake_find_active(h):
        return record if h == token_hash else None

    async def fake_find_by_uuid(self, uuid):
        return {"uuid": uuid, "current_status": "disabled"}

    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "find_active", fake_find_active, raising=False)
    monkeypatch.setattr(auth_v1.UsersDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    response = client.post("/auth/refresh", json={"refresh_token": plaintext})

    assert response.status_code == 401
    assert "账号已被禁用" in response.json()["detail"]
```

- [ ] **Step 13: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_auth_router.py::test_refresh_returns_401_when_user_disabled -v`
Expected: PASS

- [ ] **Step 14: Write `test_login_pending_deletion_recovers`**

```python
def test_login_pending_deletion_recovers(client, monkeypatch):
    """pending_deletion 且在冷却期内登录时自动恢复为 normal。"""
    from datetime import datetime, timedelta
    plain_password = "password123"
    hex_password = _sha256_hex(plain_password)
    hashed_password = _hash_password(hex_password)
    # 冷却期尚未结束（deletion_scheduled_at 在未来）
    future_time = datetime.now() + timedelta(days=15)
    user = SimpleNamespace(
        uuid="user-uuid-pending",
        password=hashed_password,
        current_status="pending_deletion",
        deletion_scheduled_at=future_time,
    )

    async def fake_find_by_username_or_email(session, login_identifier):
        return user

    captured_update = {}

    async def fake_update(self, uuid, data):
        captured_update["uuid"] = uuid
        captured_update.update(data)
        return {}

    async def fake_create_rt(user_uuid, token_hash):
        pass

    monkeypatch.setattr(auth_v1, "_login_redis_incr", lambda key, ttl: 0)
    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(auth_v1.UsersDAO, "find_by_username_or_email", fake_find_by_username_or_email, raising=False)
    monkeypatch.setattr(auth_v1.UsersDAO, "update", fake_update, raising=False)
    monkeypatch.setattr(auth_v1, "create_access_token", lambda subject: "recovered-token")
    monkeypatch.setattr(auth_v1, "generate_refresh_token", lambda: ("rt", "hash"))
    monkeypatch.setattr(auth_v1.RefreshTokensDAO, "create", fake_create_rt, raising=False)

    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": hex_password},
    )

    assert response.status_code == 200
    assert response.json()["access_token"] == "recovered-token"
    # 验证恢复了状态
    assert captured_update.get("current_status") == "normal"
    assert captured_update.get("deletion_scheduled_at") is None
```

- [ ] **Step 15: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_auth_router.py::test_login_pending_deletion_recovers -v`
Expected: PASS

- [ ] **Step 16: Write `test_login_pending_deletion_expired`**

```python
def test_login_pending_deletion_expired(client, monkeypatch):
    """pending_deletion 且冷却期已过时返回 403。"""
    from datetime import datetime, timedelta
    plain_password = "password123"
    hex_password = _sha256_hex(plain_password)
    hashed_password = _hash_password(hex_password)
    # 冷却期已过（deletion_scheduled_at 在过去）
    past_time = datetime.now() - timedelta(days=1)
    user = SimpleNamespace(
        uuid="user-uuid-expired",
        password=hashed_password,
        current_status="pending_deletion",
        deletion_scheduled_at=past_time,
    )

    async def fake_find_by_username_or_email(session, login_identifier):
        return user

    monkeypatch.setattr(auth_v1, "_login_redis_incr", lambda key, ttl: 0)
    monkeypatch.setattr(auth_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(auth_v1.UsersDAO, "find_by_username_or_email", fake_find_by_username_or_email, raising=False)
    monkeypatch.setattr(auth_v1, "verify_password", lambda p, s: True)

    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": hex_password},
    )

    assert response.status_code == 403
    assert "已永久注销" in response.json()["detail"]
```

- [ ] **Step 17: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_auth_router.py::test_login_pending_deletion_expired -v`
Expected: PASS

- [ ] **Step 18: Run full file to ensure no regressions**

Run: `pytest tests/unit/test_api_v1_auth_router.py -v`
Expected: All ~13 tests PASS

- [ ] **Step 19: Commit**

```bash
git add tests/unit/test_api_v1_auth_router.py
git commit -m "test(auth): add missing login/refresh unit tests

- disabled/banned status → 403
- IP and username rate limiting → 429
- refresh with nonexistent user → 401
- refresh with disabled user → 401
- pending_deletion recovery on login
- pending_deletion expired → 403"
```

---

### Task 2: Users router — register/complete, delete account, and missing branches

**Files:**
- Modify: `tests/unit/test_api_v1_users_router.py` (append new tests)

**Interfaces:**
- Consumes: existing helpers `_sha256_hex`, `_mock_get_session`, `_fake_questions`, `_build_sheet_data`, `_build_mock_redis`, `_VALID_REGISTER_BODY`, `_FAKE_USER`, `client` and `client_with_auth` fixtures
- Produces: 13 new test functions

- [ ] **Step 1: Write `test_register_complete_success`**

```python
# ---------------------------------------------------------------------------
# POST /users/register/complete — 完成注册 Step 2
# ---------------------------------------------------------------------------

def test_register_complete_success(monkeypatch):
    """完成注册 Step 2：设置 username + password + email，返回正式 token。"""
    from modules.api.v1 import users as users_v1
    from datetime import datetime

    app = FastAPI()
    app.include_router(users_v1.router)
    app.dependency_overrides[users_v1.get_temp_user] = lambda: {
        "uuid": "user-temp-uuid",
    }

    async def fake_find_by_username(session, username):
        return None  # username 未占用

    async def fake_find_by_username_or_email(session, login_identifier):
        return None  # email 未占用

    async def fake_update(self, uuid, data):
        return {
            "uuid": uuid,
            "nickname": "小明",
            "real_name": "王小明",
            "username": data.get("username", "testuser"),
            "email": data.get("email", "test@example.com"),
            "class": "高一(1)班",
            "class_type": "high-school",
            "user_role": "normal-user",
            "is_verified": False,
            "current_status": "normal",
        }

    async def fake_create_rt(user_uuid, token_hash):
        pass

    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1.UsersDAO, "find_by_username", fake_find_by_username)
    monkeypatch.setattr(users_v1.UsersDAO, "find_by_username_or_email", fake_find_by_username_or_email, raising=False)
    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)
    monkeypatch.setattr(users_v1, "create_access_token", lambda subject: "final-access-token")
    monkeypatch.setattr(users_v1, "generate_refresh_token", lambda: ("final-refresh-token", "hash"))
    monkeypatch.setattr(users_v1.RefreshTokensDAO, "create", fake_create_rt, raising=False)

    client = TestClient(app)
    response = client.post(
        "/users/register/complete",
        json={
            "username": "testuser",
            "password": "a" * 64,
            "email": "test@example.com",
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["access_token"] == "final-access-token"
    assert data["refresh_token"] == "final-refresh-token"
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "testuser"
    assert data["user"]["email"] == "test@example.com"
```

- [ ] **Step 2: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_register_complete_success -v`
Expected: PASS

- [ ] **Step 3: Write `test_register_complete_username_taken`**

```python
def test_register_complete_username_taken(monkeypatch):
    """username 已被其他用户使用 → 409。"""
    from modules.api.v1 import users as users_v1

    app = FastAPI()
    app.include_router(users_v1.router)
    app.dependency_overrides[users_v1.get_temp_user] = lambda: {
        "uuid": "user-temp-uuid",
    }

    async def fake_find_by_username(session, username):
        return SimpleNamespace(uuid="other-uuid")  # 已被另一个用户占用

    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1.UsersDAO, "find_by_username", fake_find_by_username)

    client = TestClient(app)
    response = client.post(
        "/users/register/complete",
        json={
            "username": "takenuser",
            "password": "a" * 64,
        },
    )

    assert response.status_code == 409
    assert "用户名已被使用" in response.json()["detail"]
```

- [ ] **Step 4: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_register_complete_username_taken -v`
Expected: PASS

- [ ] **Step 5: Write `test_register_complete_email_taken`**

```python
def test_register_complete_email_taken(monkeypatch):
    """email 已被使用 → 409。"""
    from modules.api.v1 import users as users_v1

    app = FastAPI()
    app.include_router(users_v1.router)
    app.dependency_overrides[users_v1.get_temp_user] = lambda: {
        "uuid": "user-temp-uuid",
    }

    async def fake_find_by_username(session, username):
        return None

    async def fake_find_by_username_or_email(session, login_identifier):
        return SimpleNamespace(uuid="other-uuid-by-email")  # email 已存在

    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1.UsersDAO, "find_by_username", fake_find_by_username)
    monkeypatch.setattr(users_v1.UsersDAO, "find_by_username_or_email", fake_find_by_username_or_email, raising=False)

    client = TestClient(app)
    response = client.post(
        "/users/register/complete",
        json={
            "username": "newuser",
            "password": "a" * 64,
            "email": "used@example.com",
        },
    )

    assert response.status_code == 409
    assert "邮箱已被使用" in response.json()["detail"]
```

- [ ] **Step 6: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_register_complete_email_taken -v`
Expected: PASS

- [ ] **Step 7: Write `test_register_complete_username_invalid_chars`**

```python
def test_register_complete_username_invalid_chars(monkeypatch):
    """username 含非法字符时返回 422。"""
    from modules.api.v1 import users as users_v1

    app = FastAPI()
    app.include_router(users_v1.router)
    app.dependency_overrides[users_v1.get_temp_user] = lambda: {
        "uuid": "user-temp-uuid",
    }

    client = TestClient(app)
    response = client.post(
        "/users/register/complete",
        json={
            "username": "user@name!",  # 仅允许字母数字下划线
            "password": "a" * 64,
        },
    )

    assert response.status_code == 422
```

- [ ] **Step 8: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_register_complete_username_invalid_chars -v`
Expected: PASS

- [ ] **Step 9: Write `test_register_complete_password_not_hex64`**

```python
def test_register_complete_password_not_hex64(monkeypatch):
    """password 不是 64 字符 hex 时返回 422。"""
    from modules.api.v1 import users as users_v1

    app = FastAPI()
    app.include_router(users_v1.router)
    app.dependency_overrides[users_v1.get_temp_user] = lambda: {
        "uuid": "user-temp-uuid",
    }

    client = TestClient(app)
    # 密码太短
    response = client.post(
        "/users/register/complete",
        json={
            "username": "validuser",
            "password": "short",
        },
    )
    assert response.status_code == 422

    # 密码包含非 hex 字符
    response = client.post(
        "/users/register/complete",
        json={
            "username": "validuser",
            "password": "z" + "0" * 63,
        },
    )
    assert response.status_code == 422
```

- [ ] **Step 10: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_register_complete_password_not_hex64 -v`
Expected: PASS

- [ ] **Step 11: Write `test_delete_account_success`**

```python
# ---------------------------------------------------------------------------
# DELETE /users/me — 账号注销（30 天冷却期）
# ---------------------------------------------------------------------------

def test_delete_account_success(monkeypatch):
    """正常注销 → 设置 pending_deletion + 30 天冷却期。"""
    from modules.api.v1 import users as users_v1

    user = {**_FAKE_USER, "password": _OLD_HEX}
    app = FastAPI()
    app.include_router(users_v1.router)
    app.dependency_overrides[users_v1.get_current_user] = lambda: user

    captured_update = {}

    async def fake_find_password_hash(session, user_uuid):
        return _OLD_HEX

    async def fake_update(self, uuid, data):
        captured_update.update(data)
        captured_update["uuid"] = uuid
        return {**user, **data}

    async def fake_revoke_all(user_uuid):
        pass

    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1.UsersDAO, "find_password_hash", fake_find_password_hash)
    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)
    monkeypatch.setattr(users_v1.RefreshTokensDAO, "revoke_all_for_user", fake_revoke_all)
    monkeypatch.setattr(users_v1, "invalidate_user_cache", lambda u: None)

    client = TestClient(app)
    response = client.delete("/users/me", json={"password": _OLD_HEX})

    assert response.status_code == 200
    assert "冷却期" in response.json()["message"]
    assert captured_update.get("current_status") == "pending_deletion"
    assert captured_update.get("deletion_scheduled_at") is not None
```

- [ ] **Step 12: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_delete_account_success -v`
Expected: PASS

- [ ] **Step 13: Write `test_delete_account_wrong_password`**

```python
def test_delete_account_wrong_password(monkeypatch):
    """密码错误 → 400。"""
    from modules.api.v1 import users as users_v1

    user = {**_FAKE_USER, "password": _OLD_HEX}
    app = FastAPI()
    app.include_router(users_v1.router)
    app.dependency_overrides[users_v1.get_current_user] = lambda: user

    async def fake_find_password_hash(session, user_uuid):
        return _OLD_HEX

    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1.UsersDAO, "find_password_hash", fake_find_password_hash)

    client = TestClient(app)
    response = client.delete("/users/me", json={"password": _WRONG_HEX})

    assert response.status_code == 400
    assert "密码不正确" in response.json()["detail"]
```

- [ ] **Step 14: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_delete_account_wrong_password -v`
Expected: PASS

- [ ] **Step 15: Write `test_delete_account_no_password_set`**

```python
def test_delete_account_no_password_set(monkeypatch):
    """账号未设置密码 → 400。"""
    from modules.api.v1 import users as users_v1

    user = {**_FAKE_USER, "password": None}
    app = FastAPI()
    app.include_router(users_v1.router)
    app.dependency_overrides[users_v1.get_current_user] = lambda: user

    async def fake_find_password_hash(session, user_uuid):
        return None

    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1.UsersDAO, "find_password_hash", fake_find_password_hash)

    client = TestClient(app)
    response = client.delete("/users/me", json={"password": _OLD_HEX})

    assert response.status_code == 400
    assert "未设置密码" in response.json()["detail"]
```

- [ ] **Step 16: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_delete_account_no_password_set -v`
Expected: PASS

- [ ] **Step 17: Write `test_delete_account_banned_status`**

```python
def test_delete_account_banned_status(monkeypatch):
    """被封禁时注销 → 403。"""
    from modules.api.v1 import users as users_v1

    user = {**_FAKE_USER, "password": _OLD_HEX, "current_status": "banned"}
    app = FastAPI()
    app.include_router(users_v1.router)
    app.dependency_overrides[users_v1.get_current_user] = lambda: user

    client = TestClient(app)
    response = client.delete("/users/me", json={"password": _OLD_HEX})

    assert response.status_code == 403
    assert "账号状态异常" in response.json()["detail"]
```

- [ ] **Step 18: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_delete_account_banned_status -v`
Expected: PASS

- [ ] **Step 19: Write `test_read_users_me_not_found`**

```python
def test_read_users_me_not_found(monkeypatch):
    """GET /users/me 用户不存在 → 404。"""
    from modules.api.v1 import users as users_v1

    app = FastAPI()
    app.include_router(users_v1.router)
    app.dependency_overrides[users_v1.get_current_user] = lambda: {"uuid": "nonexistent-uuid"}

    async def fake_find_by_uuid(self, uuid):
        return None

    monkeypatch.setattr(users_v1.UsersDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    client = TestClient(app)
    response = client.get("/users/me")

    assert response.status_code == 404
    assert "用户不存在" in response.json()["detail"]
```

- [ ] **Step 20: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_read_users_me_not_found -v`
Expected: PASS

- [ ] **Step 21: Write `test_change_password_db_error_returns_500`**

```python
def test_change_password_db_error_returns_500(client_with_auth, monkeypatch):
    """修改密码时 DB 更新抛出异常 → 500。"""
    async def fake_update(self, uuid, data):
        raise Exception("DB connection lost")

    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)

    response = client_with_auth.patch(
        "/users/me/password",
        json={"old_password": _OLD_HEX, "new_password": _NEW_HEX},
    )
    assert response.status_code == 500
    assert "密码修改失败" in response.json()["detail"]
```

- [ ] **Step 22: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_change_password_db_error_returns_500 -v`
Expected: PASS

- [ ] **Step 23: Write `test_change_password_user_not_found`**

```python
def test_change_password_user_not_found(client_with_auth, monkeypatch):
    """修改密码时用户不存在（update 返回 None）→ 404。"""
    async def fake_update(self, uuid, data):
        return None

    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)

    response = client_with_auth.patch(
        "/users/me/password",
        json={"old_password": _OLD_HEX, "new_password": _NEW_HEX},
    )
    assert response.status_code == 404
    assert "用户不存在" in response.json()["detail"]
```

- [ ] **Step 24: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_change_password_user_not_found -v`
Expected: PASS

- [ ] **Step 25: Write `test_update_profile_db_error_returns_500`**

```python
def test_update_profile_db_error_returns_500(profile_client, monkeypatch):
    """修改个人信息时 DB 更新抛出异常 → 500。"""
    async def fake_update(self, uuid, data):
        raise Exception("DB failure")

    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)

    response = profile_client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "新昵称"},
    )
    assert response.status_code == 500
    assert "个人信息修改失败" in response.json()["detail"]
```

- [ ] **Step 26: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_update_profile_db_error_returns_500 -v`
Expected: PASS

- [ ] **Step 27: Write `test_register_db_error_returns_500`**

```python
def test_register_db_error_returns_500(client, monkeypatch):
    """注册时 UsersDAO.create 抛出异常 → 500。"""
    questions = _fake_questions()
    sheet_data = _build_sheet_data(questions)
    mock_redis, mock_get_int = _build_mock_redis(sheet_data)

    async def fake_find_duplicate(session, real_name, class_):
        return None

    async def fake_create_raise(self, data):
        raise Exception("DB insert failed")

    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    monkeypatch.setattr(users_v1, "_redis_get_int", mock_get_int)
    monkeypatch.setattr(users_v1.UsersDAO, "find_duplicate_student", fake_find_duplicate)
    monkeypatch.setattr(users_v1.UsersDAO, "create", fake_create_raise, raising=False)

    response = client.post("/api/v1/users/register", json=_VALID_REGISTER_BODY)
    assert response.status_code == 500
    assert "注册失败" in response.json()["detail"]
```

- [ ] **Step 28: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_users_router.py::test_register_db_error_returns_500 -v`
Expected: PASS

- [ ] **Step 29: Run full file to verify no regressions**

Run: `pytest tests/unit/test_api_v1_users_router.py -v`
Expected: All ~25 tests PASS

- [ ] **Step 30: Commit**

```bash
git add tests/unit/test_api_v1_users_router.py
git commit -m "test(users): add complete_register, delete_account, and missing branch tests

- register/complete success + username/email conflicts + validation
- delete account success + wrong/no password + banned status
- read_users_me not found → 404
- change_password DB error + user not found
- update_profile DB error
- register DB error → 500"
```

---

### Task 3: Admin router — reset-password, sensitive-data, batch-delete, and missing branches

**Files:**
- Modify: `tests/unit/test_admin_router.py` (append new tests before existing helpers / after last test)

**Interfaces:**
- Consumes: existing `admin_client` fixture, `_mock_get_session` from imported helpers
- Produces: 10 new test functions

- [ ] **Step 1: Write `test_admin_reset_password_success`**

```python
# ---------------------------------------------------------------------------
# POST /admin/users/{user_uuid}/reset-password
# ---------------------------------------------------------------------------

def test_admin_reset_password_success(admin_client, monkeypatch):
    """管理员重置密码成功。"""
    from modules.api.v1 import admin as admin_v1

    # 确保 SUPER_PASSWORD 可用
    monkeypatch.setattr("core.config.settings.SUPER_PASSWORD", "super-secret")

    async def fake_update(self, uuid, data):
        return {"uuid": uuid, "password": data.get("password")}

    async def fake_revoke_all(user_uuid):
        pass

    monkeypatch.setattr(admin_v1.UsersDAO, "update", fake_update, raising=False)
    monkeypatch.setattr(admin_v1, "invalidate_user_cache", _mock_invalidate)
    monkeypatch.setattr(admin_v1.RefreshTokensDAO, "revoke_all_for_user", fake_revoke_all)

    resp = admin_client.post(
        "/admin/users/u-1/reset-password",
        json={"super_password": "super-secret", "new_password": "a" * 64},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "密码重置成功"
```

- [ ] **Step 2: Run and verify pass**

Run: `pytest tests/unit/test_admin_router.py::test_admin_reset_password_success -v`
Expected: PASS

- [ ] **Step 3: Write `test_admin_reset_password_requires_super_password`**

```python
def test_admin_reset_password_requires_super_password(admin_client, monkeypatch):
    """重置密码时超级密码错误 → 403。"""
    monkeypatch.setattr("core.config.settings.SUPER_PASSWORD", "real-secret")

    resp = admin_client.post(
        "/admin/users/u-1/reset-password",
        json={"super_password": "wrong-password", "new_password": "a" * 64},
    )
    assert resp.status_code == 403
    assert "超级密码错误" in resp.json()["detail"]
```

- [ ] **Step 4: Run and verify pass**

Run: `pytest tests/unit/test_admin_router.py::test_admin_reset_password_requires_super_password -v`
Expected: PASS

- [ ] **Step 5: Write `test_admin_reset_password_user_not_found`**

```python
def test_admin_reset_password_user_not_found(admin_client, monkeypatch):
    """重置密码时用户不存在 → 404。"""
    from modules.api.v1 import admin as admin_v1

    monkeypatch.setattr("core.config.settings.SUPER_PASSWORD", "super-secret")

    async def fake_update(self, uuid, data):
        return None

    monkeypatch.setattr(admin_v1.UsersDAO, "update", fake_update, raising=False)

    resp = admin_client.post(
        "/admin/users/nonexistent-uuid/reset-password",
        json={"super_password": "super-secret", "new_password": "a" * 64},
    )
    assert resp.status_code == 404
    assert "用户不存在" in resp.json()["detail"]
```

- [ ] **Step 6: Run and verify pass**

Run: `pytest tests/unit/test_admin_router.py::test_admin_reset_password_user_not_found -v`
Expected: PASS

- [ ] **Step 7: Write `test_admin_reset_password_invalid_new_password`**

```python
def test_admin_reset_password_invalid_new_password(admin_client, monkeypatch):
    """新密码不是 64 字符 hex → 422。"""
    monkeypatch.setattr("core.config.settings.SUPER_PASSWORD", "super-secret")

    resp = admin_client.post(
        "/admin/users/u-1/reset-password",
        json={"super_password": "super-secret", "new_password": "short"},
    )
    assert resp.status_code == 422
```

- [ ] **Step 8: Run and verify pass**

Run: `pytest tests/unit/test_admin_router.py::test_admin_reset_password_invalid_new_password -v`
Expected: PASS

- [ ] **Step 9: Write `test_admin_sensitive_data_success`**

```python
# ---------------------------------------------------------------------------
# POST /admin/users/sensitive-data
# ---------------------------------------------------------------------------

def test_admin_sensitive_data_success(admin_client, monkeypatch):
    """查看敏感信息成功，返回 real_name 和 class。"""
    from modules.api.v1 import admin as admin_v1

    monkeypatch.setattr("core.config.settings.SUPER_PASSWORD", "super-secret")

    async def fake_find_by_uuids(session, uuids):
        return [
            {"uuid": "u-1", "real_name": "张三", "class": "高一(1)班"},
            {"uuid": "u-2", "real_name": "李四", "class": "高二(2)班"},
        ]

    monkeypatch.setattr(admin_v1.UsersDAO, "find_by_uuids", fake_find_by_uuids)
    monkeypatch.setattr(admin_v1, "get_session", _fake_session)

    resp = admin_client.post(
        "/admin/users/sensitive-data",
        json={"super_password": "super-secret", "uuids": ["u-1", "u-2"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "data" in data
    assert data["data"]["u-1"]["real_name"] == "张三"
    assert data["data"]["u-1"]["class"] == "高一(1)班"
    assert data["data"]["u-2"]["real_name"] == "李四"
```

- [ ] **Step 10: Run and verify pass**

Run: `pytest tests/unit/test_admin_router.py::test_admin_sensitive_data_success -v`
Expected: PASS

- [ ] **Step 11: Write `test_admin_sensitive_data_requires_super_password`**

```python
def test_admin_sensitive_data_requires_super_password(admin_client, monkeypatch):
    """查看敏感信息时超级密码错误 → 403。"""
    monkeypatch.setattr("core.config.settings.SUPER_PASSWORD", "real-secret")

    resp = admin_client.post(
        "/admin/users/sensitive-data",
        json={"super_password": "wrong-password", "uuids": ["u-1"]},
    )
    assert resp.status_code == 403
```

- [ ] **Step 12: Run and verify pass**

Run: `pytest tests/unit/test_admin_router.py::test_admin_sensitive_data_requires_super_password -v`
Expected: PASS

- [ ] **Step 13: Write `test_admin_batch_delete_users_success`**

```python
# ---------------------------------------------------------------------------
# DELETE /admin/users/batch — 批量删除用户
# ---------------------------------------------------------------------------

def test_admin_batch_delete_users_success(admin_client, monkeypatch):
    """批量删除用户成功。"""
    from modules.api.v1 import admin as admin_v1

    monkeypatch.setattr("core.config.settings.SUPER_PASSWORD", "super-secret")

    async def fake_batch_delete(session, uuids):
        return len(uuids)

    monkeypatch.setattr(admin_v1.UsersDAO, "batch_delete", fake_batch_delete)
    monkeypatch.setattr(admin_v1, "get_session", _fake_session)
    monkeypatch.setattr(admin_v1, "_batch_invalidate_user_cache", lambda uuids: None)

    resp = admin_client.post(
        "/admin/users/batch",
        json={"uuids": ["u-1", "u-2"], "super_password": "super-secret"},
    )
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 2
```

- [ ] **Step 14: Run and verify pass**

Run: `pytest tests/unit/test_admin_router.py::test_admin_batch_delete_users_success -v`
Expected: PASS

- [ ] **Step 15: Write `test_admin_batch_delete_users_requires_super_password`**

```python
def test_admin_batch_delete_users_requires_super_password(admin_client, monkeypatch):
    """批量删除时超级密码错误 → 403。"""
    monkeypatch.setattr("core.config.settings.SUPER_PASSWORD", "real-secret")

    resp = admin_client.post(
        "/admin/users/batch",
        json={"uuids": ["u-1"], "super_password": "wrong"},
    )
    assert resp.status_code == 403
```

- [ ] **Step 16: Run and verify pass**

Run: `pytest tests/unit/test_admin_router.py::test_admin_batch_delete_users_requires_super_password -v`
Expected: PASS

- [ ] **Step 17: Write `test_admin_batch_delete_users_contains_self`**

```python
def test_admin_batch_delete_users_contains_self(admin_client, monkeypatch):
    """批量删除列表包含当前管理员 → 400。"""
    monkeypatch.setattr("core.config.settings.SUPER_PASSWORD", "super-secret")
    # admin_client 的当前用户 uuid 是 "admin-uuid"

    resp = admin_client.post(
        "/admin/users/batch",
        json={"uuids": ["admin-uuid", "u-2"], "super_password": "super-secret"},
    )
    assert resp.status_code == 400
    assert "当前登录的管理员账户" in resp.json()["detail"]
```

- [ ] **Step 18: Run and verify pass**

Run: `pytest tests/unit/test_admin_router.py::test_admin_batch_delete_users_contains_self -v`
Expected: PASS

- [ ] **Step 19: Write `test_admin_list_users_filters`**

```python
# ---------------------------------------------------------------------------
# GET /admin/users — 筛选参数
# ---------------------------------------------------------------------------

def test_admin_list_users_filters(admin_client, monkeypatch):
    """GET /admin/users 传筛选参数，确认参数正确传递给 DAO。"""
    from modules.api.v1 import admin as admin_v1

    captured = {}

    async def fake_search(session, keyword=None, status=None, role=None, limit=100, offset=0):
        captured.update(keyword=keyword, status=status, role=role, limit=limit, offset=offset)
        return []

    monkeypatch.setattr(admin_v1.UsersDAO, "search_users", fake_search, raising=False)

    resp = admin_client.get("/admin/users?keyword=alice&status=normal&role=normal-user&limit=50&offset=10")
    assert resp.status_code == 200
    assert captured["keyword"] == "alice"
    assert captured["status"] == "normal"
    assert captured["role"] == "normal-user"
    assert captured["limit"] == 50
    assert captured["offset"] == 10
```

- [ ] **Step 20: Run and verify pass**

Run: `pytest tests/unit/test_admin_router.py::test_admin_list_users_filters -v`
Expected: PASS

- [ ] **Step 21: Write `test_admin_users_total`**

```python
# ---------------------------------------------------------------------------
# GET /admin/users/total
# ---------------------------------------------------------------------------

def test_admin_users_total(admin_client, monkeypatch):
    """GET /admin/users/total 返回用户总数。"""
    from modules.api.v1 import admin as admin_v1

    async def fake_count(session, keyword=None, status=None, role=None):
        return 42

    monkeypatch.setattr(admin_v1.UsersDAO, "count_users", fake_count, raising=False)
    monkeypatch.setattr(admin_v1, "get_session", _fake_session)

    resp = admin_client.get("/admin/users/total")
    assert resp.status_code == 200
    assert resp.json()["total"] == 42
```

- [ ] **Step 22: Run and verify pass**

Run: `pytest tests/unit/test_admin_router.py::test_admin_users_total -v`
Expected: PASS

- [ ] **Step 23: Run full file to verify no regressions**

Run: `pytest tests/unit/test_admin_router.py -v`
Expected: All ~22 tests PASS

- [ ] **Step 24: Commit**

```bash
git add tests/unit/test_admin_router.py
git commit -m "test(admin): add reset-password, sensitive-data, batch-delete, and filter tests

- reset-password: success + super password check + user not found + validation
- sensitive-data: success + super password check
- batch-delete: success + super password check + self check
- list users with filters (keyword/status/role/limit/offset)
- users/total endpoint"
```

---

### Task 4: Admin questions — duplicate options and update boundary tests

**Files:**
- Modify: `tests/unit/test_api_v1_admin_questions.py` (append new tests)

**Interfaces:**
- Consumes: existing `client` fixture
- Produces: 4 new test functions

- [ ] **Step 1: Write `test_create_question_choice_rejects_duplicate_options`**

```python
def test_create_question_choice_rejects_duplicate_options(client, monkeypatch):
    """选择题选项重复时返回 422。"""
    payload = {
        "question": "测试重复选项？",
        "question_type": "choice",
        "answer": "A",
        "options": ["A", "A", "B"],  # 选项 A 重复
    }
    response = client.post("/admin/questions", json=payload)
    assert response.status_code == 422
```

- [ ] **Step 2: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_admin_questions.py::test_create_question_choice_rejects_duplicate_options -v`
Expected: PASS

- [ ] **Step 3: Write `test_update_question_true_false_validates_answer`**

```python
def test_update_question_true_false_validates_answer(client, monkeypatch):
    """编辑判断题时答案非 true/false → 400。"""
    from modules.api.v1 import admin as admin_module

    async def fake_find_by_uuid(self, uuid):
        return {"uuid": uuid, "question_type": "true_false"}

    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    response = client.patch(
        "/admin/questions/q-1",
        json={"answer": "maybe"},  # 判断题只允许 true/false
    )
    assert response.status_code == 400
    assert "判断题" in response.json()["detail"]
```

- [ ] **Step 4: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_admin_questions.py::test_update_question_true_false_validates_answer -v`
Expected: PASS

- [ ] **Step 5: Write `test_update_question_at_least_one_field`**

```python
def test_update_question_at_least_one_field(client, monkeypatch):
    """编辑题目时未提供任何字段 → 422。"""
    from modules.api.v1 import admin as admin_module

    async def fake_find_by_uuid(self, uuid):
        return {"uuid": uuid, "question_type": "choice"}

    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    response = client.patch("/admin/questions/q-1", json={})
    assert response.status_code == 422
```

- [ ] **Step 6: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_admin_questions.py::test_update_question_at_least_one_field -v`
Expected: PASS

- [ ] **Step 7: Write `test_update_question_choice_answer_not_in_options`**

```python
def test_update_question_choice_answer_not_in_options(client, monkeypatch):
    """编辑选择题时答案不在选项内 → 400。"""
    from modules.api.v1 import admin as admin_module

    async def fake_find_by_uuid(self, uuid):
        return {"uuid": uuid, "question_type": "choice"}

    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    response = client.patch(
        "/admin/questions/q-1",
        json={"answer": "C", "options": ["A", "B"]},
    )
    assert response.status_code == 400
    assert "答案必须在选项中" in response.json()["detail"]
```

- [ ] **Step 8: Run and verify pass**

Run: `pytest tests/unit/test_api_v1_admin_questions.py::test_update_question_choice_answer_not_in_options -v`
Expected: PASS

- [ ] **Step 9: Run full file to verify no regressions**

Run: `pytest tests/unit/test_api_v1_admin_questions.py -v`
Expected: All ~18 tests PASS

- [ ] **Step 10: Commit**

```bash
git add tests/unit/test_api_v1_admin_questions.py
git commit -m "test(admin-questions): add duplicate options and update validation tests

- create question rejects duplicate options → 422
- update true_false validates answer → 400
- update question requires at least one field → 422
- update choice validates answer in options → 400"
```

---

### Task 5: Final verification

- [ ] **Step 1: Run all unit tests**

Run: `pytest tests/unit/ --tb=short -v`
Expected: All ~80+ tests PASS

- [ ] **Step 2: Commit any final fixes**

If any tests fail, fix and re-run until all pass.

- [ ] **Step 3: Push / PR**

```bash
git push
```
