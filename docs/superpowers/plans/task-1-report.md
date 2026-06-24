# Task 1 Report: Auth Router — login/refresh missing branches

## Commits Made

1. `de63042` (preexisting base)
2. A new commit adding 8 test functions to `tests/unit/test_api_v1_auth_router.py`

## Test Run Output (all 18 tests, one-liner)

```
tests/unit/test_api_v1_auth_router.py::test_jwt_handler_raises_when_secret_key_missing PASSED
tests/unit/test_api_v1_auth_router.py::test_generate_refresh_token_returns_distinct_plaintext_and_hash PASSED
tests/unit/test_api_v1_auth_router.py::test_login_success_returns_bearer_token PASSED
tests/unit/test_api_v1_auth_router.py::test_login_returns_401_when_user_not_found PASSED
tests/unit/test_api_v1_auth_router.py::test_login_returns_401_when_password_invalid PASSED
tests/unit/test_api_v1_auth_router.py::test_read_users_me_returns_current_user_payload PASSED
tests/unit/test_api_v1_auth_router.py::test_refresh_token_success PASSED
tests/unit/test_api_v1_auth_router.py::test_refresh_token_returns_401_for_unknown_token PASSED
tests/unit/test_api_v1_auth_router.py::test_logout_revokes_refresh_token PASSED
tests/unit/test_api_v1_auth_router.py::test_logout_requires_authentication PASSED
tests/unit/test_api_v1_auth_router.py::test_login_returns_403_when_disabled PASSED
tests/unit/test_api_v1_auth_router.py::test_login_returns_403_when_banned PASSED
tests/unit/test_api_v1_auth_router.py::test_login_returns_429_when_ip_rate_limited PASSED
tests/unit/test_api_v1_auth_router.py::test_login_returns_429_when_username_rate_limited PASSED
tests/unit/test_api_v1_auth_router.py::test_refresh_returns_401_when_user_not_found PASSED
tests/unit/test_api_v1_auth_router.py::test_refresh_returns_401_when_user_disabled PASSED
tests/unit/test_api_v1_auth_router.py::test_login_pending_deletion_recovers PASSED
tests/unit/test_api_v1_auth_router.py::test_login_pending_deletion_expired PASSED
```

## Concerns

- No concerns. All 8 new tests pass individually and as part of the full suite. The existing 10 tests remain unaffected.
- The `test_login_pending_deletion_recovers` test captures the `update()` call's data to verify that `current_status` was set to `"normal"` and `deletion_scheduled_at` to `None`, confirming the auto-recovery logic is exercised.
- The rate limit tests rely on inspecting the Redis key string for `"ip:"` / `"un:"` substrings to determine which threshold to trigger. This matches the key format in the production code (`f"login_atm:ip:{client_ip}:min"` / `f"login_atm:un:{body.username}:min"`).
