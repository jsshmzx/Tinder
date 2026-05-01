"""Integration tests — Auth endpoints with real PostgreSQL + Redis backend.

Covers:
  * POST /api/v1/auth/login with real database and password hashing
  * GET /api/v1/auth/me with real JWT token validation
"""

import pytest
import uuid as uuid_lib

from core.security.hash import get_password_hash
from core.database.dao.users import UsersDAO


@pytest.fixture
def test_user(db_session_factory):
    """创建测试用户并在测试结束后清理。"""
    session = db_session_factory()

    # 创建测试用户
    from core.database.dao.users import User
    test_uuid = str(uuid_lib.uuid4())
    hashed_password = get_password_hash("testpassword123")

    user = User(
        uuid=test_uuid,
        username="testuser",
        email="testuser@example.com",
        real_name="Test User Real Name",
        nickname="Test User",
        password=hashed_password,
        user_role="user"
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    yield user

    # 清理
    session.delete(user)
    session.commit()
    session.close()


# ---------------------------------------------------------------------------
# POST /api/v1/auth/login
# ---------------------------------------------------------------------------

def test_login_success_with_real_database(integration_client, test_user):
    """测试使用真实数据库的成功登录。"""
    print("\n[TEST][AUTH] POST /api/v1/auth/login → 使用用户名应返回 access_token")

    response = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "testpassword123"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 0


def test_login_with_email(integration_client, test_user):
    """测试使用 email 登录。"""
    print("\n[TEST][AUTH] POST /api/v1/auth/login → 使用 email 应成功登录")

    response = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser@example.com", "password": "testpassword123"},
    )

    assert response.status_code == 200
    assert "access_token" in response.json()


def test_login_fails_with_wrong_password(integration_client, test_user):
    """测试错误密码登录失败。"""
    print("\n[TEST][AUTH] POST /api/v1/auth/login → 错误密码应返回 401")

    response = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "wrongpassword"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码错误"


def test_login_fails_with_nonexistent_user(integration_client):
    """测试不存在的用户登录失败。"""
    print("\n[TEST][AUTH] POST /api/v1/auth/login → 不存在的用户应返回 401")

    response = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "nonexistentuser", "password": "anypassword"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码错误"


# ---------------------------------------------------------------------------
# GET /api/v1/auth/me
# ---------------------------------------------------------------------------

def test_read_users_me_with_valid_token(integration_client, test_user):
    """测试使用有效 token 获取当前用户信息。"""
    print("\n[TEST][AUTH] GET /api/v1/auth/me → 有效 token 应返回用户信息")

    # 先登录获取 token
    login_response = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "testpassword123"},
    )
    token = login_response.json()["access_token"]

    # 使用 token 获取用户信息
    response = integration_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["uuid"] == test_user.uuid
    assert data["real_name"] == "Test User Real Name"
    assert data["role"] == "user"


def test_read_users_me_fails_without_token(integration_client):
    """测试没有 token 时无法获取用户信息。"""
    print("\n[TEST][AUTH] GET /api/v1/auth/me → 无 token 应返回 401")

    response = integration_client.get("/api/v1/auth/me")

    assert response.status_code == 401


def test_read_users_me_fails_with_invalid_token(integration_client):
    """测试使用无效 token 无法获取用户信息。"""
    print("\n[TEST][AUTH] GET /api/v1/auth/me → 无效 token 应返回 401")

    response = integration_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid_token_12345"},
    )

    assert response.status_code == 401
