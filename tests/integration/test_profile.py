"""Integration tests — PATCH /users/me/password and PATCH /users/me/profile
with real PostgreSQL + Redis backend.

Covers:
  * PATCH /api/v1/users/me/password — change password (old-password verification)
  * PATCH /api/v1/users/me/profile  — update nickname / real_name / class

All tests use real DB & Redis (see conftest.py).
"""

import uuid as uuid_lib
from datetime import date

import pytest

from core.database.dao.users import User
from core.security.hash import get_password_hash, verify_password


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PWD_CHG_KEY_PREFIX = "user:pwd_chg:"


def _flush_pwd_chg_keys(redis_client) -> None:
    """清除 Redis 中所有修改密码限速计数键。"""
    for key in redis_client.scan_iter("user:pwd_chg:*"):
        redis_client.delete(key)


def _login(integration_client, username: str, password: str) -> str:
    """辅助：登录并返回 JWT access_token。"""
    resp = integration_client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
    )
    assert resp.status_code == 200, f"登录失败: {resp.text}"
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def profile_user(db_session_factory):
    """创建一个带密码的测试用户，测试结束后清理。"""
    session = db_session_factory()
    test_uuid = str(uuid_lib.uuid4())
    unique_suffix = test_uuid[:8]
    hashed = get_password_hash("OldPassword123")

    user = User(
        uuid=test_uuid,
        username=f"profile_user_{unique_suffix}",
        email=f"profile_{unique_suffix}@example.com",
        real_name="测试姓名",
        nickname="测试昵称",
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
    """创建另一个测试用户，用于检测重复姓名+班级冲突。"""
    session = db_session_factory()
    test_uuid = str(uuid_lib.uuid4())
    unique_suffix = test_uuid[:8]

    user = User(
        uuid=test_uuid,
        username=f"another_user_{unique_suffix}",
        email=f"another_{unique_suffix}@example.com",
        real_name="唯一姓名冲突",
        nickname="另一位用户",
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
    """每个测试前后清除修改密码的 Redis 限速键，保证测试隔离。"""
    _flush_pwd_chg_keys(redis_client)
    yield
    _flush_pwd_chg_keys(redis_client)


# ---------------------------------------------------------------------------
# PATCH /api/v1/users/me/password
# ---------------------------------------------------------------------------


def test_change_password_success(integration_client, profile_user, db_session_factory):
    """旧密码正确、新密码合法时修改成功，数据库中密码实际被更新。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/password → 成功修改密码")

    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": "NewPassword456"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "密码修改成功"

    # 验证数据库中的密码已被更新
    session = db_session_factory()
    updated = session.query(User).filter_by(uuid=profile_user.uuid).first()
    session.close()
    assert updated is not None
    assert verify_password("NewPassword456", updated.password), "数据库中的新密码哈希应匹配"
    assert not verify_password("OldPassword123", updated.password), "旧密码应不再有效"


def test_change_password_allows_login_with_new_password(integration_client, profile_user):
    """修改密码后应能使用新密码登录，旧密码失效。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/password → 修改后可用新密码登录")

    token = _login(integration_client, profile_user.username, "OldPassword123")

    integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": "BrandNew789"},
        headers={"Authorization": f"Bearer {token}"},
    )

    # 新密码应可以登录
    new_login_resp = integration_client.post(
        "/api/v1/auth/login",
        data={"username": profile_user.username, "password": "BrandNew789"},
    )
    assert new_login_resp.status_code == 200, "应能使用新密码登录"

    # 旧密码应无法登录
    old_login_resp = integration_client.post(
        "/api/v1/auth/login",
        data={"username": profile_user.username, "password": "OldPassword123"},
    )
    assert old_login_resp.status_code == 401, "旧密码应失效"


def test_change_password_returns_400_when_old_password_wrong(integration_client, profile_user):
    """旧密码错误时返回 400。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/password → 旧密码错误应返回 400")

    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "WrongOldPassword", "new_password": "NewPassword456"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400
    assert "旧密码不正确" in response.json()["detail"]


def test_change_password_returns_400_when_new_same_as_old(integration_client, profile_user):
    """新密码与旧密码相同时返回 400。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/password → 新旧密码相同应返回 400")

    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": "OldPassword123"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400
    assert "新密码不能与旧密码相同" in response.json()["detail"]


def test_change_password_returns_400_when_account_has_no_password(
    integration_client, db_session_factory
):
    """账号未设置密码时返回 400。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/password → 账号无密码应返回 400")

    from core.security.jwt_handler import create_access_token

    session = db_session_factory()
    test_uuid = str(uuid_lib.uuid4())
    unique_suffix = test_uuid[:8]
    # 创建无密码用户
    user = User(
        uuid=test_uuid,
        username=f"no_pwd_user_{unique_suffix}",
        email=f"no_pwd_{unique_suffix}@example.com",
        real_name="无密码用户",
        nickname="无密码",
        class_="高一(9)班",
        class_type="high-school",
        password=None,  # 无密码
        user_role="normal-user",
        current_status="normal",
        is_verified=False,
    )
    session.add(user)
    session.commit()

    try:
        # 直接签发 token（因为该账号没有密码，无法通过正常 login 流程）
        token = create_access_token(subject=test_uuid)

        response = integration_client.patch(
            "/api/v1/users/me/password",
            json={"old_password": "anything", "new_password": "NewPassword456"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 400
        assert "未设置密码" in response.json()["detail"]
    finally:
        session.delete(user)
        session.commit()
        session.close()


def test_change_password_returns_422_when_new_password_too_short(integration_client, profile_user):
    """新密码不足 8 个字符时返回 422。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/password → 新密码过短应返回 422")

    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": "Short1"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422


def test_change_password_returns_422_when_new_password_has_surrounding_spaces(
    integration_client, profile_user
):
    """新密码首尾包含空格时返回 422。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/password → 新密码有前导空格应返回 422")

    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": " NewPassword456 "},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422


def test_change_password_returns_401_without_token(integration_client):
    """未提供 token 时返回 401。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/password → 无 token 应返回 401")

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": "NewPassword456"},
    )

    assert response.status_code == 401


def test_change_password_enforces_rate_limit(integration_client, profile_user, redis_client):
    """当日修改密码尝试次数达上限（10 次）后应返回 429。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/password → 超 10 次限制应返回 429")

    token = _login(integration_client, profile_user.username, "OldPassword123")

    # 预置 Redis 计数器至上限
    today = date.today().isoformat()
    redis_client.set(f"user:pwd_chg:{profile_user.uuid}:{today}", 10)

    response = integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": "NewPassword456"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 429
    assert "今日修改密码次数已达上限" in response.json()["detail"]


def test_change_password_revokes_refresh_token(integration_client, test_user):
    """修改密码并提供 refresh_token 后，该 token 应被吊销。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/password → 修改密码同时吊销 Refresh Token")

    login = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "testpassword123"},
    )
    tokens = login.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    change = integration_client.patch(
        "/api/v1/users/me/password",
        json={
            "old_password": "testpassword123",
            "new_password": "newtestpassword456",
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

    # Restore password so test_user fixture cleanup works
    login2 = integration_client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "newtestpassword456"},
    )
    new_access = login2.json()["access_token"]
    integration_client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "newtestpassword456", "new_password": "testpassword123"},
        headers={"Authorization": f"Bearer {new_access}"},
    )


# ---------------------------------------------------------------------------
# PATCH /api/v1/users/me/profile
# ---------------------------------------------------------------------------


def test_update_profile_nickname_only(integration_client, profile_user, db_session_factory):
    """仅更新昵称时成功，返回更新后的用户信息，且数据库已持久化。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/profile → 更新昵称成功")

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

    # 验证数据库已持久化
    session = db_session_factory()
    updated = session.query(User).filter_by(uuid=profile_user.uuid).first()
    session.close()
    assert updated.nickname == "全新昵称"


def test_update_profile_real_name_only(integration_client, profile_user, db_session_factory):
    """仅更新真实姓名时成功（无同名同班级冲突）。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/profile → 仅更新 real_name 成功")

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
    """仅更新班级时成功（无同名同班级冲突）。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/profile → 仅更新 class 成功")

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
    """同时更新多个字段时成功，返回完整更新后的用户信息。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/profile → 同时更新多个字段成功")

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
    """将 real_name+class 更新为自己当前的值（自身不冲突）应成功。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/profile → 更新为自身现有值不触发冲突")

    token = _login(integration_client, profile_user.username, "OldPassword123")

    # 提交与当前数据库中相同的 real_name + class
    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"real_name": profile_user.real_name, "class": profile_user.class_},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200


def test_update_profile_returns_409_on_duplicate_student(
    integration_client, profile_user, another_user
):
    """将 real_name+class 修改为已被其他用户占用时返回 409。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/profile → 重复姓名+班级应返回 409")

    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"real_name": another_user.real_name, "class": another_user.class_},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 409
    assert "已存在" in response.json()["detail"]


def test_update_profile_returns_422_when_no_fields_provided(integration_client, profile_user):
    """不提供任何字段时返回 422。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/profile → 无字段应返回 422")

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
    """nickname 包含控制字符时返回 422。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/profile → 控制字符应返回 422")

    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "bad\x01name"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422


def test_update_profile_returns_401_without_token(integration_client):
    """未提供 token 时返回 401。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/profile → 无 token 应返回 401")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "无鉴权"},
    )

    assert response.status_code == 401


def test_update_profile_strips_whitespace_from_nickname(
    integration_client, profile_user, db_session_factory
):
    """昵称首尾空白应被自动剥除（field_validator 中的 strip()）。"""
    print("\n[TEST][Profile] PATCH /api/v1/users/me/profile → 昵称前后空白应被去除")

    token = _login(integration_client, profile_user.username, "OldPassword123")

    response = integration_client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "  前后有空格  "},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    # Pydantic validator 中 strip() 去除了首尾空格
    assert response.json()["nickname"] == "前后有空格"
