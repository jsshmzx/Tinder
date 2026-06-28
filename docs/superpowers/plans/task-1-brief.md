# Task 1 Brief: Auth Router — login/refresh missing branches

**Files:**
- Modify: `tests/unit/test_api_v1_auth_router.py`

**Context:** This is Task 1 of 5 in a plan to add ~37 missing unit tests. This task adds 8 new test functions to the existing auth router test file.

**Existing imports/fixtures/helpers in the file:**
- `_sha256_hex(text)` — double SHA256 hex
- `_hash_password(hex_str)` — from `core.security.password.hash_password`
- `_mock_get_session()` — async context manager yielding `object()`
- `client` — `TestClient` fixture with `auth_v1.router` included
- `auth_v1` — imported as `from modules.api.v1 import auth as auth_v1`

**8 tests to append (before the last line of the file):**

1. `test_login_returns_403_when_disabled` — disabled status → 403, detail contains "账号已被禁用"
2. `test_login_returns_403_when_banned` — banned status → 403, detail contains "账号已被禁用"
3. `test_login_returns_429_when_ip_rate_limited` — mock `_login_redis_incr` to return > `LOGIN_MAX_ATTEMPTS_PER_IP_PER_MINUTE` for IP keys → 429
4. `test_login_returns_429_when_username_rate_limited` — mock for username keys → 429
5. `test_refresh_returns_401_when_user_not_found` — `UsersDAO().find_by_uuid` returns None → 401 "用户不存在"
6. `test_refresh_returns_401_when_user_disabled` — user has `current_status: "disabled"` → 401 "账号已被禁用"
7. `test_login_pending_deletion_recovers` — `deletion_scheduled_at` in future → auto-recover to normal + 200
8. `test_login_pending_deletion_expired` — `deletion_scheduled_at` in past → 403 "已永久注销"

**For pending_deletion tests:**
- User object needs `uuid`, `password`, `current_status="pending_deletion"`, `deletion_scheduled_at`
- Use `datetime.now() + timedelta(days=15)` for future, `datetime.now() - timedelta(days=1)` for past
- The recovery test must capture the `update()` call to verify `current_status="normal"` and `deletion_scheduled_at=None`

**All tests must:**
- Use `monkeypatch.setattr` for DAO methods and Redis interactions
- Use `SimpleNamespace` for user objects
- Use `_mock_get_session()` for DB session context
- Pass with `pytest tests/unit/test_api_v1_auth_router.py::test_name -v`
- Follow existing code style (comments in Chinese, same indentation)

**Report contract:** Write report to `docs/superpowers/plans/task-1-report.md` containing:
- List of commits made
- Test run output (one-liner per test)
- Any concerns
