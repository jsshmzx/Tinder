# Task 2 Brief: Users Router — register/complete, delete account, missing branches

**Files:**
- Modify: `tests/unit/test_api_v1_users_router.py`

**Context:** This is Task 2 of 5. This task adds 13 new test functions to the existing users router test file.

**Existing imports/fixtures/helpers in the file (already at the top):**
```python
import hashlib
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.config import settings
from modules.api.v1 import users as users_v1
```

**Existing helper functions (reuse these!):**
- `_sha256_hex(text)` — double SHA256 hex
- `_mock_get_session()` — returns async context manager yielding `object()`
- `_fake_questions(count=5)` — returns list of question dicts with uuid/question/answer
- `_build_sheet_data(questions, ip="127.0.0.1")` — returns sheet dict with questions/answers
- `_build_mock_redis(sheet_data, ip_count=0, name_count=0, sheet_count=0)` — returns (mock_redis, get_int_func)
- `_VALID_REGISTER_BODY` — dict with valid register request body
- `_FAKE_USER` — dict with user fields (uuid, nickname, real_name, class, class_type, user_role, is_verified, current_status, password)
- `_OLD_HEX`, `_NEW_HEX`, `_WRONG_HEX` — pre-computed hex passwords
- `client` fixture — TestClient with users_v1.router prefix /api/v1
- `client_with_auth` fixture — TestClient with get_current_user dependency override
- `profile_client` fixture — TestClient for profile update tests

**IMPORTANT: The file already has these fixtures defined at the module level. You just need to use them in your tests. Do NOT re-import or redefine them.**

**13 tests to append at the end of the file:**

### register/complete tests:

1. `test_register_complete_success` — normal completion → 201 + access_token + refresh_token + user data
2. `test_register_complete_username_taken` — username conflict → 409 "用户名已被使用"
3. `test_register_complete_email_taken` — email conflict → 409 "邮箱已被使用"
4. `test_register_complete_username_invalid_chars` — username with "@!" chars → 422
5. `test_register_complete_password_not_hex64` — short password + non-hex password → 422

### delete account tests:

6. `test_delete_account_success` — normal → 200 + pending_deletion status
7. `test_delete_account_wrong_password` — wrong password → 400 "密码不正确"
8. `test_delete_account_no_password_set` — no password set → 400 "未设置密码"
9. `test_delete_account_banned_status` — banned → 403 "账号状态异常"

### existing endpoint branches:

10. `test_read_users_me_not_found` — find_by_uuid returns None → 404 "用户不存在"
11. `test_change_password_db_error_returns_500` — update raises Exception → 500 "密码修改失败"
12. `test_change_password_user_not_found` — update returns None → 404 "用户不存在"
13. `test_update_profile_db_error_returns_500` — update raises Exception → 500 "个人信息修改失败"

### Implementation notes:

**For register/complete tests (1-5):**
- Build a fresh FastAPI app in each test (do NOT use the `client` fixture)
- Override `get_temp_user` via `app.dependency_overrides[users_v1.get_temp_user] = lambda: {"uuid": "user-temp-uuid"}`
- Mock `users_v1.get_session` with `_mock_get_session()`
- Mock `users_v1.UsersDAO.find_by_username(session, username)`
- Mock `users_v1.UsersDAO.find_by_username_or_email(session, login_identifier)` — need `raising=False` for class method
- Mock `users_v1.UsersDAO().update(uuid, data)` via `monkeypatch.setattr(users_v1.UsersDAO, "update", ...)` with `raising=False`
- Mock `users_v1.create_access_token` and `users_v1.generate_refresh_token`
- Mock `users_v1.RefreshTokensDAO.create`
- Create a `TestClient(app)` with the local app

**For delete account tests (6-9):**
- Build fresh app in each test
- Override `get_current_user` with the user dict
- Mock `users_v1.get_session`
- Mock `users_v1.UsersDAO.find_password_hash(session, user_uuid)` 
- Mock `users_v1.UsersDAO().update(uuid, data)` for the success test
- The endpoint path is `DELETE /users/me` (no prefix)

**For existing endpoint branches (10-13):**
- Test 10: use `app.dependency_overrides[users_v1.get_current_user] = lambda: {"uuid": "nonexistent-uuid"}`
- Tests 11-13: use `client_with_auth` or `profile_client` fixtures (already defined in the file)
- The `client_with_auth` fixture has verify_password mocked to compare hex values directly

**Report contract:** Write report to `docs/superpowers/plans/task-2-report.md` containing:
- Commits made
- Test run output (one-liner per test)
- Any concerns
