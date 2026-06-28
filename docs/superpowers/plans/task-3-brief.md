# Task 3 Brief: Admin Router — reset-password, sensitive-data, batch-delete, filters, total

**Files:**
- Modify: `tests/unit/test_admin_router.py`

**Context:** Task 3 of 5. Add 10 new test functions to the admin router test file.

**Existing imports/fixtures/helpers in the file (already at the top):**
```python
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from modules.api.v1 import admin as admin_v1
from core.middleware.auth.dependencies import get_current_user
from core.database.connection.pgsql import get_session
```

**Existing fixture/helper (reuse these, DO NOT redefine):**
- `@asynccontextmanager` / `async def _fake_session(*args, **kwargs)` — yields `SimpleNamespace()`
- `admin_client` — TestClient with get_current_user → superadmin, get_session → _fake_session
- `_mock_search_users`, `_mock_count_users`, `_mock_get_user_stats` — existing DAO mock helpers
- `_mock_create`, `_mock_update`, `_mock_delete` — existing instance method mocks
- `_mock_invalidate(*args, **kwargs)` — no-op cache invalidation

**IMPORTANT: The file has section comments at the top level for each endpoint. Append new tests IN THEIR CORRECT SECTION, not all at the end.**

**10 tests to add:**

### reset-password section (after line 312 area, before "sensitive-data" section):

1. `test_admin_reset_password_success` — POST /admin/users/u-1/reset-password with correct super_password → 200 "密码重置成功"
2. `test_admin_reset_password_requires_super_password` — wrong super_password → 403 "超级密码错误"
3. `test_admin_reset_password_user_not_found` — update returns None → 404 "用户不存在"
4. `test_admin_reset_password_invalid_new_password` — new_password too short → 422

### sensitive-data section:

5. `test_admin_sensitive_data_success` — POST /admin/users/sensitive-data → 200 with real_name/class in data dict
6. `test_admin_sensitive_data_requires_super_password` — wrong super_password → 403

### batch-delete section:

7. `test_admin_batch_delete_users_success` — POST /admin/users/batch → 200 {"deleted": N}
8. `test_admin_batch_delete_users_requires_super_password` — wrong super_password → 403
9. `test_admin_batch_delete_users_contains_self` — uuids list includes current admin (uuid "admin-uuid") → 400

### filters/total section:

10. `test_admin_list_users_filters` — GET /admin/users with keyword/status/role/limit/offset → verify captured params
11. `test_admin_users_total` — GET /admin/users/total → 200 {"total": 42}

**Implementation notes:**

For SUPER_PASSWORD tests:
- Set `monkeypatch.setattr("core.config.settings.SUPER_PASSWORD", "super-secret")` before each test that needs it
- The admin_client fixture already has get_current_user overridden to superadmin

For sensitive-data tests:
- Mock `admin_v1.UsersDAO.find_by_uuids(session, uuids)` — this is a class method (no `raising=False`)
- Mock `admin_v1.get_session` with `_fake_session`
- The endpoint returns `{"data": {"uuid": {"real_name": ..., "class": ...}}}`

For batch-delete tests:
- The endpoint is POST /admin/users/batch (not DELETE)
- Mock `admin_v1.UsersDAO.batch_delete(session, uuids)` — class method
- Mock `admin_v1._batch_invalidate_user_cache` — function
- The `contains_self` test: admin_client's current user is `"admin-uuid"`, so include that in the uuids list

For list users filters:
- Mock `admin_v1.UsersDAO.search_users(session, keyword, status, role, limit, offset)` — class method, use `raising=False`
- The test captures the params and asserts they match query string values

For users/total:
- Mock `admin_v1.UsersDAO.count_users(session, keyword, status, role)` — class method, use `raising=False`
- Mock `admin_v1.get_session` with `_fake_session`

**Report contract:** Write report to `docs/superpowers/plans/task-3-report.md` containing:
- Commits made
- Test run output
- Any concerns
