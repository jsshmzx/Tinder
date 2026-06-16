"""Integration tests — PATCH /users/me/password and PATCH /users/me/profile
with real PostgreSQL + Redis backend.

Covers:
  * PATCH /api/v1/users/me/password — change password (old-password verification)
  * PATCH /api/v1/users/me/profile  — update nickname / real_name / class

All tests use real DB & Redis (see conftest.py).
"""

import hashlib
import uuid as uuid_lib
from datetime import date

import pytest

from core.database.dao.users import User
from core.security.hash import get_password_hash, verify_password


def _sha256_hex(text: str) -> str:
    """Compute double SHA256 hex — matches client-side hashing."""
    return hashlib.sha256(hashlib.sha256(text.encode()).hexdigest().encode()).hexdigest()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PWD_CHG_KEY_PREFIX = "user:pwd_chg:"


def _flush_pwd_chg_keys(redis_client) -> None:
    """Clear Redis rate-limit keys for password changes."""
    for key in redis_client.scan_iter("user:pwd_chg:*"):
        redis_client.delete(key)


def _login(integration_client, username: str, password: str) -> str:
    """Helper: login and return JWT access_token."""
    hex_password = _sha256_hex(password)
    resp = integration_client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": hex_password},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def profile_user(db_session_factory):
    """Create a test user with a proper password and clean up after."""
    session = db_session_factory()
    test_uuid = str(uuid_lib.uuid4())
    unique_suffix = test_uuid[:8]
    plain_pw = "OldPassword123"
    hex_pw = _sha256_hex(plain_pw)
    hashed = get_password_hash(hex_pw)

    user = User(
        uuid=test_uuid,
        username=f"profile_user_{unique_suffix}",
        email=f"profile_{unique_suffix}@example.com",
        real_name="Test Real Name",
        nickname="Test Nickname",
        class_="高一(1)班",
        class_type="high-school",
        password=hashed,
        user_role="normal-user",
        current_status="normal",
        is_verified=False,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    yield user

    session.delete(user)
    session.commit()
    session.close()


@pytest.fixture
def another_user(db_session_factory):
    """Create another test user for duplicate name+class conflict tests."""
    session = db_session_factory()
    test_uuid = str(uuid_lib.uuid4())
    unique_suffix = test_uuid[:8]

    user = User(
        uuid=test_uuid,
        username=f"another_user_{unique_suffix}",
        email=f"another_{unique_suffix}@example.com",
        real_name="Unique Name Conflict",
        nickname="Another User",
        class_="高二(2)班",
        class_type="high-school",
        user_role="normal-user",
        current_status="normal",
        is_verified=False,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    yield user

    session.delete(user)
    session.commit()
    session.close()


@pytest.fixture(autouse=True)
def flush_pwd_chg_keys(redis_client):
    """Clear password-change Redis keys before and after each test."""
    _flush_pwd_chg_keys(redis_client)
    yield
    _flush_pwd_chg_keys(redis_client)


@pytest.fixture
def _test_user_for_refresh_test(db_session_factory):
    """Ensure a test_user exists for refresh-token revocation tests.

    This mirrors the user created in test_auth.py so that the
    test_change_password_revokes_refresh_token test can use it.
    """
    session = db_session_factory()
    test_uuid = str(uuid_lib.uuid4())
    plain_pw = "testpassword123"
    hex_pw = _sha256_hex(plain_pw)
    hashed = get_password_hash(hex_pw)

    user = User(
        uuid=test_uuid,
        username="testuser_integration",
        email="testuser_integration@example.com",
        real_name="Test User Integration",
        nickname="Test User",
        password=hashed,
        user_role="normal-user",
        current_status="normal",
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    yield user

    session.delete(user)
    session.commit()
    session.close()


# ---------------------------------------------------------------------------
# PATCH /api/v1/users/me/password
# ---------------------------------------------------------------------------


def test_change_password_success(integration_client, profile_user, db_session_factory):
    """Correct old password + valid new password should succeed and update the DB."""
    token = _login(integration_client, profile_user.username, "OldPassword123")
    new_hex = _sha256_hex("NewPassword456")

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": _sha256_hex("OldPassword123"), "new_password": new_hex},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "密码修改成功"

    # Verify the password was actually updated in the database
    session = db_session_factory()
    updated = session.query(User).filter_by(uuid=profile_user.uuid).first()
    session.close()
    assert updated is not None
    assert verify_password(new_hex, updated.password), "New password hash should match"
    old_hex = _sha256_hex("OldPassword123")
    assert not verify_password(old_hex, updated.password), "Old password should no longer be valid"


def test_change_password_allows_login_with_new_password(integration_client, profile_user):
    """After changing password, the new password should work for login and the old should fail."""
    token = _login(integration_client, profile_user.username, "OldPassword123")
    new_hex = _sha256_hex("BrandNew789")

    integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": _sha256_hex("OldPassword123"), "new_password": new_hex},
        headers={"Authorization": f"Bearer {token}"},
    )

    # New password should work
    new_login = integration_client.post(
        "/api/v1/auth/login",
        json={"username": profile_user.username, "password": new_hex},
    )
    assert new_login.status_code == 200, "Should be able to login with new password"

    # Old password should fail
    old_login = integration_client.post(
        "/api/v1/auth/login",
        json={"username": profile_user.username, "password": _sha256_hex("OldPassword123")},
    )
    assert old_login.status_code == 401, "Old password should be invalid"


def test_change_password_returns_400_when_old_password_wrong(integration_client, profile_user):
    """Wrong old password should return 400."""
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={
            "old_password": _sha256_hex("WrongOldPassword"),
            "new_password": _sha256_hex("NewPassword456"),
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400
    assert "旧密码不正确" in response.json()["detail"]


def test_change_password_returns_400_when_new_same_as_old(integration_client, profile_user):
    """Same old and new password should return 400."""
    old_hex = _sha256_hex("OldPassword123")
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": old_hex, "new_password": old_hex},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400
    assert "新密码不能与旧密码相同" in response.json()["detail"]


def test_change_password_returns_400_when_account_has_no_password(
    integration_client, db_session_factory
):
    """Account with no password set should return 400."""
    from core.security.jwt_handler import create_access_token

    session = db_session_factory()
    test_uuid = str(uuid_lib.uuid4())
    unique_suffix = test_uuid[:8]
    user = User(
        uuid=test_uuid,
        username=f"no_pwd_user_{unique_suffix}",
        email=f"no_pwd_{unique_suffix}@example.com",
        real_name="No Password User",
        nickname="No Password",
        class_="高一(9)班",
        class_type="high-school",
        password=None,
        user_role="normal-user",
        current_status="normal",
        is_verified=False,
    )
    session.add(user)
    session.commit()

    try:
        token = create_access_token(subject=test_uuid)

        response = integration_client.patch(
            "/api/v1/users/me/password",
            json={"old_password": "any", "new_password": _sha256_hex("NewPassword456")},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 400
        assert "未设置密码" in response.json()["detail"]
    finally:
        session.delete(user)
        session.commit()
        session.close()


def test_change_password_returns_422_when_new_password_too_short(integration_client, profile_user):
    """New password that is not 64-char hex should return 422."""
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": _sha256_hex("OldPassword123"), "new_password": "Short1"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422


def test_change_password_returns_401_without_token(integration_client):
    """Without token should return 401."""
    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "any", "new_password": "another"},
    )

    assert response.status_code == 401


def test_change_password_enforces_rate_limit(integration_client, profile_user, redis_client):
    """Daily password change attempts should be rate-limited (10/day)."""
    token = _login(integration_client, profile_user.username, "OldPassword123")
    today = date.today().isoformat()
    redis_client.set(f"user:pwd_chg:{profile_user.uuid}:{today}", 10)

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={
            "old_password": _sha256_hex("OldPassword123"),
            "new_password": _sha256_hex("NewPassword456"),
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 429
    assert "今日修改密码次数已达上限" in response.json()["detail"]


def test_change_password_revokes_refresh_token(
    integration_client, _test_user_for_refresh_test, db_session_factory
):
    """Changing password with a refresh_token should revoke that token."""
    data = _login(integration_client, "testuser_integration", "testpassword123")
    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    change = integration_client.patch(
        "/api/v1/users/me/password",
        json={
            "old_password": _sha256_hex("testpassword123"),
            "new_password": _sha256_hex("newtestpassword456"),
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

    # Restore password so fixture cleanup still works
    data2 = _login(integration_client, "testuser_integration", "newtestpassword456")
    new_access = data2["access_token"]
    integration_client.patch(
        "/api/v1/users/me/password",
        json={
            "old_password": _sha256_hex("newtestpassword456"),
            "new_password": _sha256_hex("testpassword123"),
        },
        headers={"Authorization": f"Bearer {new_access}"},
    )


# ---------------------------------------------------------------------------
# PATCH /api/v1/users/me/profile
# ---------------------------------------------------------------------------


def test_update_profile_nickname_only(integration_client, profile_user, db_session_factory):
    """Updating only nickname should succeed and persist to DB."""
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "全新昵称"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["nickname"] == "全新昵称"
    assert data["uuid"] == profile_user.uuid

    session = db_session_factory()
    updated = session.query(User).filter_by(uuid=profile_user.uuid).first()
    session.close()
    assert updated.nickname == "全新昵称"


def test_update_profile_real_name_only(integration_client, profile_user, db_session_factory):
    """Updating only real_name should succeed (no conflict)."""
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"real_name": "新真实姓名"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["real_name"] == "新真实姓名"

    session = db_session_factory()
    updated = session.query(User).filter_by(uuid=profile_user.uuid).first()
    session.close()
    assert updated.real_name == "新真实姓名"


def test_update_profile_class_only(integration_client, profile_user, db_session_factory):
    """Updating only class should succeed (no conflict)."""
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"class": "高二(5)班"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["class"] == "高二(5)班"

    session = db_session_factory()
    updated = session.query(User).filter_by(uuid=profile_user.uuid).first()
    session.close()
    assert updated.class_ == "高二(5)班"


def test_update_profile_multiple_fields(integration_client, profile_user, db_session_factory):
    """Updating multiple fields simultaneously should succeed."""
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "多字段昵称", "real_name": "多字段姓名", "class": "高三(4)班"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["nickname"] == "多字段昵称"
    assert data["real_name"] == "多字段姓名"
    assert data["class"] == "高三(4)班"
    assert data["uuid"] == profile_user.uuid

    session = db_session_factory()
    updated = session.query(User).filter_by(uuid=profile_user.uuid).first()
    session.close()
    assert updated.nickname == "多字段昵称"
    assert updated.real_name == "多字段姓名"
    assert updated.class_ == "高三(4)班"


def test_update_profile_same_real_name_and_class_is_allowed_for_self(
    integration_client, profile_user
):
    """Setting real_name+class to the same values already owned should succeed."""
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"real_name": profile_user.real_name, "class": profile_user.class_},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200


def test_update_profile_returns_409_on_duplicate_student(
    integration_client, profile_user, another_user
):
    """Setting real_name+class to values occupied by another user should return 409."""
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"real_name": another_user.real_name, "class": another_user.class_},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 409
    assert "已存在" in response.json()["detail"]


def test_update_profile_returns_422_when_no_fields_provided(integration_client, profile_user):
    """Providing no fields should return 422."""
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422


def test_update_profile_returns_422_on_control_char_in_nickname(
    integration_client, profile_user
):
    """Nickname containing control characters should return 422."""
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "bad\x01name"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422


def test_update_profile_returns_401_without_token(integration_client):
    """Without token should return 401."""
    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "No Auth"},
    )

    assert response.status_code == 401


def test_update_profile_strips_whitespace_from_nickname(
    integration_client, profile_user, db_session_factory
):
    """Nickname whitespace should be stripped by field_validator."""
    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "  spaces around  "},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["nickname"] == "spaces around"
