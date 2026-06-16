"""Integration tests — Auth endpoints with real PostgreSQL + Redis backend.

Covers:
  * POST /api/v1/auth/login with real database and password verification
  * GET /api/v1/users/me with real JWT token validation
  * POST /api/v1/auth/refresh — token rotation
  * POST /api/v1/auth/logout — revoke refresh token
"""

import hashlib
import uuid as uuid_lib

import pytest

from core.database.dao.users import UsersDAO
from core.security.hash import verify_password


def _sha256_hex(text: str) -> str:
    """Compute double SHA256 hex — matches client-side hashing used by login."""
    return hashlib.sha256(hashlib.sha256(text.encode()).hexdigest().encode()).hexdigest()


@pytest.fixture
def test_user(db_session_factory):
    """Create a test user with a properly hashed password and clean up after the session."""
    session = db_session_factory()
    test_uuid = str(uuid_lib.uuid4())
    plain_pw = "testpassword123"
    hex_pw = _sha256_hex(plain_pw)
    # get_password_hash is a pass-through, so storing hex_pw directly is fine
    from core.security.hash import get_password_hash
    hashed_password = get_password_hash(hex_pw)

    from core.database.dao.users import User
    user = User(
        uuid=test_uuid,
        username="testuser",
        email="testuser@example.com",
        real_name="Test User",
        nickname="Test User",
        password=hashed_password,
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


def _login(integration_client, username: str, password: str) -> dict:
    """Helper: login and return the JSON response body."""
    hex_password = _sha256_hex(password)
    resp = integration_client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": hex_password},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()


# ---------------------------------------------------------------------------
# POST /api/v1/auth/login
# ---------------------------------------------------------------------------


def test_login_success_with_real_database(integration_client, test_user):
    """Login with the test user's credentials should return tokens."""
    data = _login(integration_client, "testuser", "testpassword123")
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 0
    assert len(data["refresh_token"]) > 0


def test_login_with_email(integration_client, test_user):
    """Login should work with email as well as username."""
    data = _login(integration_client, "testuser@example.com", "testpassword123")
    assert "access_token" in data
    assert "refresh_token" in data


def test_login_fails_with_wrong_password(integration_client, test_user):
    """Wrong password should return 401."""
    hex_wrong = _sha256_hex("wrongpassword")
    response = integration_client.post(
        "/api/v1/auth/login",
        json={"username": "testuser", "password": hex_wrong},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码错误"


def test_login_fails_with_nonexistent_user(integration_client):
    """Non-existent user should return 401."""
    hex_any = _sha256_hex("anything")
    response = integration_client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistentuser", "password": hex_any},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码错误"


# ---------------------------------------------------------------------------
# GET /api/v1/users/me  (on users router, not auth)
# ---------------------------------------------------------------------------


def test_read_users_me_with_valid_token(integration_client, test_user):
    """Authenticated request should return the current user's info."""
    data = _login(integration_client, "testuser", "testpassword123")
    token = data["access_token"]

    response = integration_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["uuid"] == test_user.uuid
    assert user_data["real_name"] == "Test User"
    assert user_data["user_role"] == "normal-user"


def test_read_users_me_fails_without_token(integration_client):
    """Unauthenticated request should return 401."""
    response = integration_client.get("/api/v1/users/me")
    assert response.status_code == 401


def test_read_users_me_fails_with_invalid_token(integration_client):
    """Invalid JWT should return 401."""
    response = integration_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer invalid_token_12345"},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/v1/auth/refresh
# ---------------------------------------------------------------------------


def test_refresh_token_issues_new_token_pair(integration_client, test_user):
    """Refreshing should return new access_token and refresh_token."""
    data = _login(integration_client, "testuser", "testpassword123")
    refresh_token = data["refresh_token"]
    old_access_token = data["access_token"]

    response = integration_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 200
    new_data = response.json()
    assert "access_token" in new_data
    assert "refresh_token" in new_data
    assert new_data["access_token"] != old_access_token
    assert new_data["refresh_token"] != refresh_token


def test_refresh_token_revokes_old_token(integration_client, test_user):
    """After refresh, the old refresh token should be revoked."""
    data = _login(integration_client, "testuser", "testpassword123")
    refresh_token = data["refresh_token"]

    # First refresh succeeds
    r1 = integration_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert r1.status_code == 200

    # Reusing the same (now-revoked) token must fail
    r2 = integration_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert r2.status_code == 401


def test_refresh_token_fails_for_invalid_token(integration_client):
    """Completely invalid refresh token should return 401."""
    response = integration_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": "completely-invalid-token"}
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/v1/auth/logout
# ---------------------------------------------------------------------------


def test_logout_revokes_refresh_token(integration_client, test_user):
    """Logout should revoke the refresh token."""
    import hashlib
    data = _login(integration_client, "testuser", "testpassword123")
    refresh_token = data["refresh_token"]
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

    response = integration_client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {data['access_token']}"},
    )
    assert response.status_code == 200

    # Refresh token should now be revoked
    r2 = integration_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert r2.status_code == 401


def test_logout_requires_authentication(integration_client):
    """Logout without auth should return 401."""
    response = integration_client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": "any-token"},
    )
    assert response.status_code == 401
