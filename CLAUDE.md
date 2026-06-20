# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run database migrations (required before first start)
python db_migrate.py

# Start the server (port 1912, hot-reload enabled)
python server.py

# Run all tests
pytest

# Run only unit tests (no DB/Redis required)
pytest tests/unit/ --tb=short

# Run integration tests (requires real PostgreSQL + Redis via env vars)
pytest tests/integration/ --tb=short

# Run a single test
pytest tests/unit/test_api_v1_auth_router.py::test_login -v
```

Integration tests require `DATABASE_URL` and `REDIS_URL` env vars pointing at test instances (e.g. `postgresql://postgres:pw@localhost:5432/tinder_test` and `redis://localhost:6379/0`).

## Architecture

**Entry point:** `server.py` creates the FastAPI app, registers middleware, and mounts routers. Docs (`/docs`, `/redoc`) are disabled when `APP_ENV` is not `development`.

**Routers:**
- `modules/index/index.py` — root health-check router
- `modules/api/v1/router.py` — aggregates `auth`, `users`, and `admin` sub-routers under `/api/v1`

**Core layers (`core/`):**
- `core/database/connection/pgsql.py` — async SQLAlchemy engine + `get_session()` context manager; always use `async with get_session() as session:`
- `core/database/connection/redis.py` — synchronous Redis client wrapper (`redis_conn`). Uses `RedisConnectionManager` with a background monitor thread and exponential-backoff reconnection. Call `redis_conn.get_client()` to get the `Redis | None` instance — never create a raw Redis client.
- `core/database/dao/base.py` — `BaseDAO` with generic async CRUD (`find_by_uuid`, `find_all`, `create`, `update`, `delete`). All DAOs set a `MODEL` class attribute pointing to their SQLAlchemy ORM model. **Column name mapping:** `_data_to_kwargs()` converts DB column names (`class`) to ORM attribute names (`class_`) automatically using the `__mapper__.column_attrs` mapping — you map the DB column name in `update()` call data, not the attribute name.
- `core/middleware/firewall/` — `FirewallMiddleware` runs on every request: IP ban → rate limit → crawler UA → attack signatures (XSS/SQLi/path traversal/SSRF). Violations are persisted to `illegal_requests` and counted in Redis; exceeding `_BAN_THRESHOLD` triggers an IP ban
- `core/middleware/auth/dependencies.py` — `get_current_user` decodes JWT, then checks a 60-second Redis cache (`auth:user:<uuid>`) before hitting PostgreSQL. `RoleChecker` and `MinRoleChecker` are FastAPI `Depends`-compatible guards. `get_temp_user` validates a separate token with `purpose="register_complete"` (for the registration step 2 flow).
- `core/security/rbac.py` — three roles in ascending power: `normal-user < songlist_editor < superadmin`. Higher roles automatically pass lower-role gates
- `core/security/hash.py` — password handling: `get_password_hash(pwd)` → bcrypt; `verify_password(pwd, hashed)` → bcrypt verify. **Important:** passwords arrive from the client as a 64-char SHA256 hex string (double-hashed by the client) and are then bcrypt-hashed server-side before storage.
- `core/security/jwt_handler.py` — JWT creation/decode, refresh token generation (SHA256 hash stored, plaintext returned to client), and temp token creation (with `purpose` in payload).
- `core/config.py` — `settings` singleton reads from `.env` / environment variables. Config keys are defined as class attributes on the `Settings` class. Add new keys by adding a class attribute. Dotenv is loaded at module import time.
- `core/cron/scheduler.py` — APScheduler `AsyncIOScheduler`. Add new cron tasks by calling `scheduler.add_job(...)` inside the `start()` function. Currently only `cleanup_expired_deletions` runs at `CRON_CLEANUP_INTERVAL_HOURS` (default 1h).
- `core/helper/CustomLog/index.py` — `CustomLog` (alias `CtLog`) is the sole logging mechanism; never use `print()`

**Registration flow (three steps):**
1. `POST /api/v1/users/register/sheet/request` — quiz-based application: get a random sheet of 5 questions (stored in Redis TTL'd). Rate-limited per-IP per-day.
2. `POST /api/v1/users/register` — submit answers (must get ≥3 correct); if successful, create a user row with `password=NULL` and issue a temp JWT (15 min, `purpose="register_complete"`).
3. `POST /api/v1/users/register/complete` — use the temp token to set `username`, `password`, and optional `email`. Returns a real JWT + refresh token.

**Admin security pattern:** High-risk operations (delete users) require a `super_password` field in the request body, validated against `SUPER_PASSWORD` env var. This is **in addition to** RBAC (superadmin role required). Never skip the super password check.

**CI workflows:** `.github/workflows/` — `test.yml` (pytest), `docker-build.yml`, `codeql.yml`, `codacy.yml`.

**Refresh token rotation:**
- On `/auth/login` → generate a new refresh token (SHA256 hash stored, plaintext returned).
- On `/auth/refresh` → revoke the old hash, issue a new token (rotation).
- On password change → `revoke_all_for_user()` invalidates all sessions.
- Old tokens cleaned up by the cron task after `REFRESH_TOKEN_CLEANUP_DAYS` (default 7).

## Database migrations

Migrations are plain SQL files under `core/database/migrations/SQL/`. The ordered list in `core/database/migrations/migration_history.py` controls execution order — `db_migrate.py` runs each file exactly once and records it in `migration_history` table.

- New table: `initial_<tablename>.sql`
- Schema change: `alter_<tablename>_<description>.sql`
- After adding a SQL file, append its filename to `migration_history` list
- Use `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` in all migration SQL

## Auth & RBAC usage pattern

```python
from core.middleware.auth.dependencies import get_current_user, MinRoleChecker, invalidate_user_cache
from core.security.rbac import Role

# Any authenticated user
@router.get("/me")
async def endpoint(user: dict = Depends(get_current_user)):
    ...

# Minimum role required (superadmin also passes a songlist_editor gate)
@router.post("/admin-only")
async def admin_endpoint(_: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value))):
    ...
```

After modifying a user record, call `invalidate_user_cache(user_uuid)` to clear the Redis cache.

## CustomLog (CtLog) usage guide

Located at `core/helper/CustomLog/index.py`. Call via `CustomLog(...)` or the shorter alias `CtLog(...)`.

| Parameter    | Type              | Default    | Description                                      |
|-------------|-------------------|-----------|--------------------------------------------------|
| `log_level`  | `str`             | `"INFO"`   | `INFO` / `WARNING` / `ERROR` / `SUCCESS`         |
| `content`    | `str`             | `""`       | 日志内容                                        |
| `log_style`  | `str`             | `"CT"`     | `CT`（彩色+标签）或 `NORMAL`（纯文本 `[LEVEL] 内容`） |
| `print_out`  | `bool`            | `True`     | 是否打印到控制台                                  |
| `sid`        | `bool`            | `False`    | Store In DB — 是否异步写入数据库                  |
| `sidp`       | `str`             | `"system"` | `"system"`（系统日志表）或 `"personal"`（个人日志表） |
| `log_type`   | `str \| None`     | `None`     | 写入 DB 时填充 `type` 字段（如 `"auth"`, `"cron"`) |
| `user_uuid`  | `str \| None`     | `None`     | 个人日志时需要（写入 `personal_logs.user_uuid`）  |

```python
from core.helper.CustomLog.index import CustomLog, CtLog

# 基础用法（CT 样式，不存库）— 向后兼容原 custom_log
CustomLog("SUCCESS", "操作完成")
CustomLog("WARNING", "注意：xxx")
CustomLog("ERROR", "失败: {exc}")

# NORMAL 样式（纯文本，无 ANSI 颜色）
CtLog("INFO", "普通日志", log_style="NORMAL")

# 不输出到控制台
CustomLog("INFO", "仅存库", print_out=False, sid=True, sidp="system")

# 写入个人日志表（需指定用户）
CustomLog("INFO", "用户操作", sid=True, sidp="personal",
          user_uuid=user_uuid, log_type="auth")

# 别名
CtLog("SUCCESS", "CtLog 与 CustomLog 完全等价")
```

## Code conventions

- Imports order: stdlib → third-party → `core` → `modules`
- Type annotations on all new functions
- No `print()` — use `CustomLog("INFO"|"SUCCESS"|"WARNING"|"ERROR", message)` or `CtLog(...)`
- Branch naming: `feat/`, `fix/`, `refactor/`, `docs/`
