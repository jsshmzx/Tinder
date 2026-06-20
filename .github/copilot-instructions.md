# Copilot Instructions

## Project Overview

This is **Tinder** — a FastAPI-based backend API service (航海家计划后端API服务) running on Python 3.10+.

- **Framework**: FastAPI
- **Database**: PostgreSQL (async driver: asyncpg)
- **ORM**: SQLAlchemy 2.x (async mode)
- **Cache**: Redis
- **Deployment**: Docker
- **Port**: 1912
- **Testing**: pytest + pytest-asyncio + httpx

## Development Environment Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment variables
cp .env.example .env
# Edit .env and set DATABASE_URL, REDIS_URL, APP_ENV, and JWT_SECRET_KEY

# 3. Run database migrations (requires a running PostgreSQL instance)
python db_migrate.py

# 4. Start the development server
python server.py
# Server will be available at http://localhost:1912
# Swagger UI at http://localhost:1912/docs (development mode only)
```

### Docker (recommended for local development with all services)

```bash
docker-compose up --build
```

## Build & Validation

Before committing any changes, run:

```bash
# Run unit tests (no external services required)
pytest tests/unit/ --tb=short

# Run the full test suite (requires PostgreSQL + Redis — see CI environment variables)
pytest tests/ --tb=short
```

## Testing

- Tests live under `tests/unit/` and `tests/integration/`.
- **Unit tests** (`tests/unit/`) require no external services and can always be run locally.
- **Integration tests** (`tests/integration/`) require live PostgreSQL and Redis services. Set `DATABASE_URL` and `REDIS_URL` environment variables before running them.
- Run unit tests only: `pytest tests/unit/ --tb=short`
- Run all tests: `pytest --tb=short`
- `pytest.ini` sets `pythonpath = .`, so imports like `from core.xxx import yyy` work from any test file.
- Use `pytest-asyncio` for async test functions.
- Use `httpx` for HTTP-level integration tests against the FastAPI app.
- Integration test fixtures live in `tests/integration/conftest.py`.

## Project Structure

```
├── modules/               # Feature modules
│   ├── index/             # Health-check / root endpoint
│   └── auth/              # Authentication routes (login, /me)
├── core/
│   ├── database/
│   │   ├── connection/    # pgsql.py (engine/session), redis.py (RedisConnectionManager)
│   │   ├── dao/           # DAO classes extending BaseDAO (one file per model)
│   │   └── migrations/    # SQL migration files under SQL/
│   ├── helper/
│   │   └── ContainerCustomLog/  # custom_log() logging helper
│   ├── middleware/
│   │   ├── auth/          # dependencies.py: get_current_user, RoleChecker
│   │   └── firewall/      # FirewallMiddleware (rate-limiting / IP blocking)
│   └── security/
│       ├── hash.py        # get_password_hash, verify_password (bcrypt via passlib)
│       └── jwt_handler.py # create_access_token, decode_access_token (python-jose HS256)
├── tests/
│   ├── unit/              # Unit tests (no external services)
│   └── integration/       # Integration tests (PostgreSQL + Redis required)
├── server.py              # Application entrypoint
├── db_migrate.py          # Database migration runner
├── pytest.ini             # pytest configuration
└── requirements.txt       # Python dependencies
```

## Database & ORM Conventions

- Use **async SQLAlchemy 2.x** with the **asyncpg** driver at all times.
- `get_session()` in `core/database/connection/pgsql.py` is an `@asynccontextmanager` that yields an `AsyncSession`. Always use it as `async with get_session() as session:`.
- All DAO methods must be `async`.
- `dispose_engine()` is also `async` and must be awaited.
- All ORM models must inherit from `Base` (imported from `core.database.connection.pgsql`).
- Every table must have:
  - An `id SERIAL PRIMARY KEY` column.
  - A `uuid TEXT NOT NULL UNIQUE` column.
- Timestamp columns follow the `*_at` naming convention (e.g., `created_at`, `joined_at`, `sent_at`, `updated_at`).
- Create indexes for columns frequently used in `WHERE` clauses or `JOIN`s using the pattern `idx_<tablename>_<columnname>`.
  - Example: `CREATE INDEX IF NOT EXISTS idx_tokens_belong_to ON tokens (belong_to);`

## DAO Pattern

- All DAOs extend `BaseDAO` from `core/database/dao/base.py`.
- `BaseDAO` provides: `find_by_uuid`, `find_all`, `create`, `update`, `delete`.
- Subclasses must declare a `MODEL` class attribute pointing to the corresponding ORM model class.
- Add custom query methods directly on the DAO subclass as `async` methods.

## Migrations

- SQL migration files live in `core/database/migrations/SQL/`.
- Filenames follow the pattern `initial_<tablename>.sql` for new tables, or `alter_<tablename>_<description>.sql` for alterations.
- Always use `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`.
- After adding a new SQL file, run `python db_migrate.py` to apply it.

## API & Routing

- The FastAPI `app` is created in `server.py`.
- Swagger docs (`/docs`, `/redoc`) are only enabled in `development` environment (`APP_ENV=development`). They are `None` in production.
- CORS is configured with `allow_origins=["*"]` — do not narrow this without discussion.
- `FirewallMiddleware` is registered after the CORS middleware.
- New feature routers are created in `modules/` and registered in `server.py` via `app.include_router(...)`.

## Security & Authentication

- **Password hashing**: use `get_password_hash(password)` and `verify_password(plain, hashed)` from `core.security.hash` (bcrypt via passlib).
- **JWT tokens**: use `create_access_token(subject)` and `decode_access_token(token)` from `core.security.jwt_handler`. Tokens use HS256 and expire after 7 days by default. Set `JWT_SECRET_KEY` in the environment in production.
- **Protecting routes**: use `Depends(get_current_user)` from `core.middleware.auth.dependencies` to require authentication. It validates the Bearer token and returns the current user dict.
- **Role-based access**: use `Depends(RoleChecker(["admin", "user"]))` from the same module to enforce allowed roles.

## Redis

- The global Redis connection manager singleton is `redis_conn` in `core.database.connection.redis`.
- `redis_conn.start()` is called in the application lifespan (startup); `redis_conn.stop()` is called on shutdown.
- To get the active Redis client: `redis_conn.get_client()` — returns `None` if not connected.
- Set `REDIS_URL` in the environment (e.g., `redis://localhost:6379/0`).

## Logging

- Use `custom_log(level, message)` from `core.helper.CustomLog.index` for all application logging. Do **not** use `print()` or Python's `logging` module directly.
- Supported levels: `"SUCCESS"`, `"WARNING"`, `"ERROR"` (case-insensitive).

## Environment Variables

- `DATABASE_URL` — PostgreSQL connection string (required). The app auto-converts `postgresql://` → `postgresql+asyncpg://`.
- `REDIS_URL` — Redis connection string (required, e.g., `redis://localhost:6379/0`).
- `APP_ENV` — `development` or `production` (defaults to `development`).
- `JWT_SECRET_KEY` — Secret key for signing JWT tokens. **Must be set to a strong random value in production.**
- Copy `.env.example` to `.env` for local development.

## Code Style

- **Python 3.10+** features are allowed (e.g., `X | Y` union types, `match` statements).
- Use type hints for all function signatures.
- Chinese comments are present throughout the codebase and are acceptable; new code may use English or Chinese comments consistently with the surrounding code.
- Keep imports grouped: standard library → third-party → local (`core`, `modules`).
