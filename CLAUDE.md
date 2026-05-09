# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## OpenWolf

@.wolf/OPENWOLF.md

This project uses OpenWolf for context management. Read and follow `.wolf/OPENWOLF.md` every session. Check `.wolf/cerebrum.md` before generating code. Check `.wolf/anatomy.md` before reading files.

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
- `core/database/connection/redis.py` — synchronous Redis client wrapper (`redis_conn`)
- `core/database/dao/base.py` — `BaseDAO` with generic async CRUD (`find_by_uuid`, `find_all`, `create`, `update`, `delete`). All DAOs set a `MODEL` class attribute pointing to their SQLAlchemy ORM model
- `core/middleware/firewall/` — `FirewallMiddleware` runs on every request: IP ban → rate limit → crawler UA → attack signatures (XSS/SQLi/path traversal/SSRF). Violations are persisted to `illegal_requests` and counted in Redis; exceeding `_BAN_THRESHOLD` triggers an IP ban
- `core/middleware/auth/dependencies.py` — `get_current_user` decodes JWT, then checks a 60-second Redis cache (`auth:user:<uuid>`) before hitting PostgreSQL. `RoleChecker` and `MinRoleChecker` are FastAPI `Depends`-compatible guards
- `core/security/rbac.py` — three roles in ascending power: `normal-user < songlist_editor < superadmin`. Higher roles automatically pass lower-role gates
- `core/helper/ContainerCustomLog/index.py` — `custom_log(level, message)` is the sole logging mechanism; never use `print()`

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

## Code conventions

- Imports order: stdlib → third-party → `core` → `modules`
- Type annotations on all new functions
- No `print()` — use `custom_log("INFO"|"SUCCESS"|"WARNING"|"ERROR", message)`
- Branch naming: `feat/`, `fix/`, `refactor/`, `docs/`
