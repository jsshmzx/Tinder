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

## Project Structure

```
├── modules/          # Feature modules (users, index, etc.)
├── core/
│   ├── database/
│   │   ├── connection/   # db.py (engine/session), redis.py
│   │   ├── dao/          # DAO classes extending BaseDAO
│   │   └── migrations/   # SQL migration files
│   ├── helper/           # Utility helpers (e.g., ContainerCustomLog)
│   └── middleware/       # Middleware (e.g., FirewallMiddleware)
├── tests/
│   ├── unit/             # Unit tests
│   └── integration/      # Integration tests
├── server.py             # Application entrypoint
├── db_migrate.py         # Database migration runner
├── pytest.ini            # pytest configuration
└── requirements.txt      # Python dependencies
```

## Database & ORM Conventions

- Use **async SQLAlchemy 2.x** with the **asyncpg** driver at all times.
- `get_session()` in `core/database/connection/db.py` is an `@asynccontextmanager` that yields an `AsyncSession`. Always use it as `async with get_session() as session:`.
- All DAO methods must be `async`.
- `dispose_engine()` is also `async` and must be awaited.
- All ORM models must inherit from `Base` (imported from `core.database.connection.db`).
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

## Migrations

- SQL migration files live in `core/database/migrations/SQL/`.
- Filenames follow the pattern `initial_<tablename>.sql` for new tables, or `alter_<tablename>_<description>.sql` for alterations.
- Always use `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`.

## API & Routing

- The FastAPI `app` is created in `server.py`.
- Swagger docs (`/docs`, `/redoc`) are only enabled in `development` environment (`APP_ENV=development`). They are `None` in production.
- CORS is configured with `allow_origins=["*"]` — do not narrow this without discussion.
- `FirewallMiddleware` is registered after the CORS middleware.
- New feature routers are created in `modules/` and registered in `server.py` via `app.include_router(...)`.

## Logging

- Use `custom_log(level, message)` from `core.helper.ContainerCustomLog.index` for all application logging. Do **not** use `print()` or Python's `logging` module directly.
- Supported levels: `"SUCCESS"`, `"WARNING"`, `"ERROR"` (case-insensitive).

## Environment Variables

- `DATABASE_URL` — PostgreSQL connection string (required). The app auto-converts `postgresql://` → `postgresql+asyncpg://`.
- `APP_ENV` — `development` or `production` (defaults to `development`).
- Copy `.env.example` to `.env` for local development.

## Testing

- Tests live under `tests/unit/` and `tests/integration/`.
- Run tests with: `pytest`
- `pytest.ini` sets `pythonpath = .`, so imports like `from core.xxx import yyy` work from any test file.
- Use `pytest-asyncio` for async test functions.
- Use `httpx` for HTTP-level integration tests against the FastAPI app.

## Code Style

- **Python 3.10+** features are allowed (e.g., `X | Y` union types, `match` statements).
- Use type hints for all function signatures.
- Chinese comments are present throughout the codebase and are acceptable; new code may use English or Chinese comments consistently with the surrounding code.
- Keep imports grouped: standard library → third-party → local (`core`, `modules`).
