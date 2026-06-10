"""Unit tests — modules.api.v1.users (no database, no Redis)."""

import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from modules.api.v1 import users as users_v1


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(users_v1.router, prefix="/api/v1")
    return TestClient(app)


def _mock_get_session():
    @asynccontextmanager
    async def _session_ctx():
        yield object()

    return _session_ctx


def _fake_questions(count: int = 5) -> list[dict]:
    return [
        {"uuid": f"q-uuid-{i}", "question": f"Question {i}?", "answer": f"answer{i}"}
        for i in range(1, count + 1)
    ]


def _build_sheet_data(questions: list[dict], ip: str = "127.0.0.1") -> dict:
    return {
        "questions": [{"uuid": q["uuid"], "question": q["question"]} for q in questions],
        "answers": {q["uuid"]: q["answer"].lower() for q in questions},
        "issued_ip": ip,
    }


# ---------------------------------------------------------------------------
# GET /api/v1/users/register/questions
# ---------------------------------------------------------------------------


def test_get_questions_returns_sheet(client, monkeypatch):
    """成功获取问题表，返回 sheet_id 和 5 道不含答案的题目。"""
    questions = _fake_questions()

    async def fake_find_random_active(count=5):
        return questions

    mock_redis = SimpleNamespace(
        get=lambda key: None,
        set=lambda *a, **kw: None,
        incr=lambda key: 1,
        expire=lambda key, ttl: None,
    )

    monkeypatch.setattr(users_v1.RegisterQuestionsDAO, "find_random_active", fake_find_random_active)
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    # IP 换题次数返回 0（未到上限）
    monkeypatch.setattr(users_v1, "_redis_get_int", lambda client, key: 0)

    response = client.get("/api/v1/users/register/questions")

    assert response.status_code == 200
    data = response.json()
    assert "sheet_id" in data
    assert len(data["questions"]) == 5
    # 返回的题目不应包含答案
    for q in data["questions"]:
        assert "answer" not in q
        assert "uuid" in q
        assert "question" in q


def test_get_questions_returns_429_when_ip_at_limit(client, monkeypatch):
    """IP 当天申请问题表次数达上限时返回 429。"""

    async def fake_find_random_active(count=5):
        return _fake_questions()

    mock_redis = SimpleNamespace(get=lambda k: None, set=lambda *a, **kw: None)
    monkeypatch.setattr(users_v1.RegisterQuestionsDAO, "find_random_active", fake_find_random_active)
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    # 模拟已达上限
    monkeypatch.setattr(
        users_v1,
        "_redis_get_int",
        lambda client, key: users_v1._MAX_SHEETS_PER_IP_PER_DAY,
    )

    response = client.get("/api/v1/users/register/questions")
    assert response.status_code == 429


def test_get_questions_returns_503_when_insufficient_questions(client, monkeypatch):
    """题库题目不足时返回 503。"""

    async def fake_find_random_active(count=5):
        return _fake_questions(count=2)  # 仅 2 道，不足 5 道

    mock_redis = SimpleNamespace(
        get=lambda k: None,
        set=lambda *a, **kw: None,
        incr=lambda k: 1,
        expire=lambda k, t: None,
    )
    monkeypatch.setattr(users_v1.RegisterQuestionsDAO, "find_random_active", fake_find_random_active)
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    monkeypatch.setattr(users_v1, "_redis_get_int", lambda client, key: 0)

    response = client.get("/api/v1/users/register/questions")
    assert response.status_code == 503


def test_get_questions_returns_503_when_redis_unavailable(client, monkeypatch):
    """Redis 不可用时返回 503。"""

    async def fake_find_random_active(count=5):
        return _fake_questions()

    monkeypatch.setattr(users_v1.RegisterQuestionsDAO, "find_random_active", fake_find_random_active)
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: None))

    response = client.get("/api/v1/users/register/questions")
    assert response.status_code == 503


# ---------------------------------------------------------------------------
# POST /api/v1/users/register
# ---------------------------------------------------------------------------

_VALID_REGISTER_BODY = {
    "nickname": "小明",
    "real_name": "明明",
    "classtype": "high-school",
    "class": "高一(1)班",
    "sheet_id": "test-sheet-id",
    "answers": [
        {"question_uuid": f"q-uuid-{i}", "answer": f"answer{i}"}
        for i in range(1, 6)
    ],
}


def _build_mock_redis(sheet_data: dict, ip_count: int = 0, name_count: int = 0, sheet_count: int = 0):
    """构建一个模拟 Redis 客户端（支持 get/incr/expire/delete）。"""
    _sheet_raw = json.dumps(sheet_data, ensure_ascii=False)
    _incr_store: dict[str, int] = {}
    _deleted: list = []

    def _get(key: str):
        if "qsheet:" in key and "qsheet_atm" not in key:
            return _sheet_raw
        return None

    def _incr(key: str) -> int:
        _incr_store[key] = _incr_store.get(key, 0) + 1
        return _incr_store[key]

    def _expire(key: str, ttl: int) -> None:
        pass

    def _delete(*keys) -> None:
        _deleted.extend(keys)

    def _get_int_factory(ip_c, name_c, sheet_c):
        def _get_int(client, key: str) -> int:
            if "ip_atm" in key:
                return ip_c
            if "name_atm" in key:
                return name_c
            if "qsheet_atm" in key:
                return sheet_c
            if "ip_sheets" in key:
                return 0
            return 0
        return _get_int

    return SimpleNamespace(get=_get, incr=_incr, expire=_expire, delete=_delete), _get_int_factory(
        ip_count, name_count, sheet_count
    )


def test_register_success(client, monkeypatch):
    """全部条件满足时注册成功，返回 201 和 access_token。"""
    questions = _fake_questions()
    sheet_data = _build_sheet_data(questions)
    mock_redis, mock_get_int = _build_mock_redis(sheet_data)

    async def fake_find_duplicate(session, real_name, class_):
        return None  # 无重复

    async def fake_create(self, data):
        return {
            **data,
            "id": 1,
            "joined_at": None,
            "last_login_at": None,
            "last_login_ip": None,
            "score": 0,
            "views": 0,
            "title": None,
            "invited_by": None,
            "other_info": None,
            "username": None,
            "email": None,
            "avatar_url": None,
            "password": None,
        }

    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    monkeypatch.setattr(users_v1, "_redis_get_int", mock_get_int)
    monkeypatch.setattr(users_v1.UsersDAO, "find_duplicate_student", fake_find_duplicate)
    monkeypatch.setattr(users_v1.UsersDAO, "create", fake_create, raising=False)
    monkeypatch.setattr(users_v1, "create_access_token", lambda subject: "mock-token")

    response = client.post("/api/v1/users/register", json=_VALID_REGISTER_BODY)

    assert response.status_code == 201
    data = response.json()
    assert data["access_token"] == "mock-token"
    assert data["token_type"] == "bearer"
    assert data["user"]["real_name"] == "明明"
    assert data["user"]["role"] == "normal-user"
    assert data["user"]["is_verified"] is False
    assert data["user"]["status"] == "normal"


def test_register_returns_429_when_ip_limit_reached(client, monkeypatch):
    """IP 今日注册尝试次数达上限时返回 429。"""
    questions = _fake_questions()
    sheet_data = _build_sheet_data(questions)
    mock_redis, _ = _build_mock_redis(sheet_data, ip_count=users_v1._MAX_IP_ATTEMPTS_PER_DAY)

    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    monkeypatch.setattr(
        users_v1,
        "_redis_get_int",
        lambda client, key: users_v1._MAX_IP_ATTEMPTS_PER_DAY if "ip_atm" in key else 0,
    )

    response = client.post("/api/v1/users/register", json=_VALID_REGISTER_BODY)
    assert response.status_code == 429
    assert "IP" in response.json()["detail"]


def test_register_returns_429_when_name_limit_reached(client, monkeypatch):
    """real_name 今日尝试次数达上限时返回 429。"""
    questions = _fake_questions()
    sheet_data = _build_sheet_data(questions)
    mock_redis, _ = _build_mock_redis(sheet_data, name_count=users_v1._MAX_NAME_ATTEMPTS_PER_DAY)

    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    monkeypatch.setattr(
        users_v1,
        "_redis_get_int",
        lambda client, key: (
            users_v1._MAX_NAME_ATTEMPTS_PER_DAY if "name_atm" in key else 0
        ),
    )

    response = client.post("/api/v1/users/register", json=_VALID_REGISTER_BODY)
    assert response.status_code == 429
    assert "姓名" in response.json()["detail"]


def test_register_returns_400_when_sheet_not_found(client, monkeypatch):
    """问题表不存在时返回 400。"""
    mock_redis = SimpleNamespace(
        get=lambda key: None,  # 问题表不存在
        incr=lambda k: 1,
        expire=lambda k, t: None,
    )
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    monkeypatch.setattr(users_v1, "_redis_get_int", lambda client, key: 0)

    response = client.post("/api/v1/users/register", json=_VALID_REGISTER_BODY)
    assert response.status_code == 400
    assert "问题表" in response.json()["detail"]


def test_register_returns_400_when_sheet_attempts_exceeded(client, monkeypatch):
    """问题表尝试次数达上限时返回 400。"""
    questions = _fake_questions()
    sheet_data = _build_sheet_data(questions)
    mock_redis, _ = _build_mock_redis(sheet_data, sheet_count=users_v1._MAX_SHEET_ATTEMPTS)

    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    monkeypatch.setattr(
        users_v1,
        "_redis_get_int",
        lambda client, key: users_v1._MAX_SHEET_ATTEMPTS if "qsheet_atm" in key else 0,
    )

    response = client.post("/api/v1/users/register", json=_VALID_REGISTER_BODY)
    assert response.status_code == 400
    assert "尝试次数已达上限" in response.json()["detail"]


def test_register_returns_400_when_too_few_correct_answers(client, monkeypatch):
    """答对题目不足 3 道时返回 400。"""
    questions = _fake_questions()
    sheet_data = _build_sheet_data(questions)
    mock_redis, mock_get_int = _build_mock_redis(sheet_data)

    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    monkeypatch.setattr(users_v1, "_redis_get_int", mock_get_int)
    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())

    # 所有答案都错误
    wrong_answers_body = {
        **_VALID_REGISTER_BODY,
        "answers": [
            {"question_uuid": f"q-uuid-{i}", "answer": "wrong_answer"}
            for i in range(1, 6)
        ],
    }

    response = client.post("/api/v1/users/register", json=wrong_answers_body)
    assert response.status_code == 400
    assert "答题未通过" in response.json()["detail"]


def test_register_returns_409_when_duplicate_student(client, monkeypatch):
    """数据库中已存在相同姓名+班级的学生时返回 409。"""
    questions = _fake_questions()
    sheet_data = _build_sheet_data(questions)
    mock_redis, mock_get_int = _build_mock_redis(sheet_data)

    async def fake_find_duplicate(session, real_name, class_):
        return SimpleNamespace(uuid="existing-uuid")  # 已存在

    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    monkeypatch.setattr(users_v1, "_redis_get_int", mock_get_int)
    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1.UsersDAO, "find_duplicate_student", fake_find_duplicate)

    response = client.post("/api/v1/users/register", json=_VALID_REGISTER_BODY)
    assert response.status_code == 409
    assert "已存在" in response.json()["detail"]


def test_register_returns_503_when_redis_unavailable(client, monkeypatch):
    """Redis 不可用时返回 503。"""
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: None))

    response = client.post("/api/v1/users/register", json=_VALID_REGISTER_BODY)
    assert response.status_code == 503


def test_register_rejects_invalid_classtype(client, monkeypatch):
    """classtype 不合法时返回 422。"""
    mock_redis = SimpleNamespace(get=lambda k: None)
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))

    invalid_body = {**_VALID_REGISTER_BODY, "classtype": "kindergarten"}
    response = client.post("/api/v1/users/register", json=invalid_body)
    assert response.status_code == 422


def test_register_rejects_control_chars_in_nickname(client, monkeypatch):
    """nickname 包含控制字符时返回 422。"""
    mock_redis = SimpleNamespace(get=lambda k: None)
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))

    invalid_body = {**_VALID_REGISTER_BODY, "nickname": "bad\x00name"}
    response = client.post("/api/v1/users/register", json=invalid_body)
    assert response.status_code == 422


def test_register_case_insensitive_answers(client, monkeypatch):
    """答案校验对大小写不敏感。"""
    questions = _fake_questions()
    sheet_data = _build_sheet_data(questions)
    mock_redis, mock_get_int = _build_mock_redis(sheet_data)

    async def fake_find_duplicate(session, real_name, class_):
        return None

    async def fake_create(self, data):
        return {
            **data,
            "id": 1,
            "joined_at": None,
            "last_login_at": None,
            "last_login_ip": None,
            "score": 0,
            "views": 0,
            "title": None,
            "invited_by": None,
            "other_info": None,
            "username": None,
            "email": None,
            "avatar_url": None,
            "password": None,
        }

    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    monkeypatch.setattr(users_v1, "_redis_get_int", mock_get_int)
    monkeypatch.setattr(users_v1.UsersDAO, "find_duplicate_student", fake_find_duplicate)
    monkeypatch.setattr(users_v1.UsersDAO, "create", fake_create, raising=False)
    monkeypatch.setattr(users_v1, "create_access_token", lambda subject: "mock-token")

    # 答案全部大写（原始答案为小写）
    upper_answers_body = {
        **_VALID_REGISTER_BODY,
        "answers": [
            {"question_uuid": f"q-uuid-{i}", "answer": f"ANSWER{i}"}
            for i in range(1, 6)
        ],
    }

    response = client.post("/api/v1/users/register", json=upper_answers_body)
    assert response.status_code == 201


# ---------------------------------------------------------------------------
# PATCH /api/v1/users/me/password — 修改密码
# ---------------------------------------------------------------------------

_FAKE_USER = {
    "uuid": "user-uuid-1",
    "nickname": "小明",
    "real_name": "王小明",
    "class": "高一(1)班",
    "class_type": "high-school",
    "user_role": "normal-user",
    "is_verified": False,
    "current_status": "normal",
    "password": None,  # 将在各测试中按需替换
}


@pytest.fixture()
def client_with_auth(monkeypatch) -> TestClient:
    """返回一个已注入 get_current_user 依赖覆盖的 TestClient。"""
    from core.security.hash import get_password_hash as _hash

    hashed = _hash("OldPassword123")
    user = {**_FAKE_USER, "password": hashed}

    app = FastAPI()
    app.include_router(users_v1.router, prefix="/api/v1")
    app.dependency_overrides[users_v1.get_current_user] = lambda: user
    # 禁用 Redis 限流以简化大多数密码测试
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: None))
    # Mock find_password_hash: change_password 不再从 current_user 读取密码哈希
    async def fake_find_password_hash(session, user_uuid):
        return hashed
    monkeypatch.setattr(users_v1.UsersDAO, "find_password_hash", fake_find_password_hash)
    # Mock revoke_all_for_user: 变更密码后吊销所有 token（单元测试无需真实 DB）
    async def fake_revoke_all_for_user(user_uuid):
        pass
    monkeypatch.setattr(users_v1.RefreshTokensDAO, "revoke_all_for_user", fake_revoke_all_for_user)
    return TestClient(app)


def test_change_password_success(client_with_auth, monkeypatch):
    """旧密码正确、新密码合法时修改成功，返回 200 和成功消息。"""

    async def fake_update(self, uuid, data):
        return {**_FAKE_USER, "password": data["password"]}

    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)

    response = client_with_auth.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": "NewPassword456"},
    )
    assert response.status_code == 200
    assert response.json()["message"] == "密码修改成功"


def test_change_password_returns_400_when_old_password_wrong(client_with_auth):
    """旧密码错误时返回 400。"""
    response = client_with_auth.patch(
        "/api/v1/users/me/password",
        json={"old_password": "WrongPassword!", "new_password": "NewPassword456"},
    )
    assert response.status_code == 400
    assert "旧密码不正确" in response.json()["detail"]


def test_change_password_returns_400_when_new_same_as_old(client_with_auth):
    """新密码与旧密码相同时返回 400。"""
    response = client_with_auth.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": "OldPassword123"},
    )
def test_change_password_returns_400_when_no_password_set(monkeypatch):
    """账号未设置密码时返回 400。"""
    user_no_pwd = {**_FAKE_USER, "password": None}
    app = FastAPI()
    app.include_router(users_v1.router, prefix="/api/v1")
    app.dependency_overrides[users_v1.get_current_user] = lambda: user_no_pwd
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: None))
    # Mock find_password_hash to return None (未设置密码)
    async def fake_find_password_hash(session, user_uuid):
        return None
    monkeypatch.setattr(users_v1.UsersDAO, "find_password_hash", fake_find_password_hash)
    client = TestClient(app)

    response = client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "anything", "new_password": "NewPassword456"},
    )
    assert response.status_code == 400
    assert "未设置密码" in response.json()["detail"]


def test_change_password_returns_422_when_new_password_too_short(client_with_auth):
    """新密码不足 8 个字符时返回 422。"""
    response = client_with_auth.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": "Short1"},
    )
    assert response.status_code == 422


def test_change_password_returns_422_when_new_password_has_surrounding_spaces(client_with_auth):
    """新密码首尾有空格时返回 422。"""
    response = client_with_auth.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": " NewPassword456 "},
    )
    assert response.status_code == 422


def test_change_password_returns_429_when_rate_limit_exceeded(monkeypatch):
    """当日修改密码尝试次数达上限时返回 429。"""
    from core.security.hash import get_password_hash as _hash

    hashed = _hash("OldPassword123")
    user = {**_FAKE_USER, "password": hashed}

    app = FastAPI()
    app.include_router(users_v1.router, prefix="/api/v1")
    app.dependency_overrides[users_v1.get_current_user] = lambda: user

    mock_redis = SimpleNamespace(
        get=lambda k: None,
        incr=lambda k: 1,
        expire=lambda k, t: None,
    )
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: mock_redis))
    # 模拟已达上限
    monkeypatch.setattr(
        users_v1,
        "_redis_get_int",
        lambda client, key: users_v1._MAX_PWD_CHG_ATTEMPTS_PER_DAY,
    )

    client = TestClient(app)
    response = client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": "NewPassword456"},
    )
    assert response.status_code == 429
    assert "今日修改密码次数已达上限" in response.json()["detail"]


def test_change_password_returns_403_when_account_banned(monkeypatch):
    """账号状态为 banned 时返回 403。"""
    user_banned = {**_FAKE_USER, "password": "hashed", "current_status": "banned"}
    app = FastAPI()
    app.include_router(users_v1.router, prefix="/api/v1")
    app.dependency_overrides[users_v1.get_current_user] = lambda: user_banned
    monkeypatch.setattr(users_v1, "redis_conn", SimpleNamespace(get_client=lambda: None))
    client = TestClient(app)

    response = client.patch(
        "/api/v1/users/me/password",
        json={"old_password": "anything", "new_password": "NewPassword456"},
    )
    assert response.status_code == 403
    assert "账号状态异常" in response.json()["detail"]


def test_change_password_revokes_refresh_token_when_provided(client_with_auth, monkeypatch):
    """提供 refresh_token 时，修改密码后应吊销该 token。"""
    import hashlib
    plaintext_rt = "my-current-refresh-token"
    expected_hash = hashlib.sha256(plaintext_rt.encode()).hexdigest()
    revoked = []

    async def fake_update(self, uuid, data):
        return {**_FAKE_USER, "password": data["password"]}

    async def fake_revoke(h):
        revoked.append(h)

    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)
    monkeypatch.setattr(users_v1.RefreshTokensDAO, "revoke", fake_revoke, raising=False)

    response = client_with_auth.patch(
        "/api/v1/users/me/password",
        json={
            "old_password": "OldPassword123",
            "new_password": "NewPassword456",
            "refresh_token": plaintext_rt,
        },
    )

    assert response.status_code == 200
    assert expected_hash in revoked


def test_change_password_succeeds_without_refresh_token(client_with_auth, monkeypatch):
    """不提供 refresh_token 时，修改密码成功且不调用吊销。"""
    async def fake_update(self, uuid, data):
        return {**_FAKE_USER, "password": data["password"]}

    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)

    response = client_with_auth.patch(
        "/api/v1/users/me/password",
        json={"old_password": "OldPassword123", "new_password": "NewPassword456"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "密码修改成功"


# ---------------------------------------------------------------------------
# PATCH /api/v1/users/me/profile — 修改个人信息
# ---------------------------------------------------------------------------

@pytest.fixture()
def profile_client() -> TestClient:
    """返回注入了 get_current_user 的 TestClient（用于个人信息修改测试）。"""
    app = FastAPI()
    app.include_router(users_v1.router, prefix="/api/v1")
    app.dependency_overrides[users_v1.get_current_user] = lambda: {**_FAKE_USER}
    return TestClient(app)


def test_update_profile_success_nickname(profile_client, monkeypatch):
    """仅修改昵称时成功返回更新后的用户信息。"""

    async def fake_update(self, uuid, data):
        return {**_FAKE_USER, **data}

    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)

    response = profile_client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "新昵称"},
    )
    assert response.status_code == 200
    assert response.json()["nickname"] == "新昵称"


def test_update_profile_success_real_name_and_class(profile_client, monkeypatch):
    """同时修改姓名和班级，无重复冲突时成功。"""

    async def fake_find_dup(session, real_name, class_, exclude_uuid):
        return None  # 无冲突

    async def fake_update(self, uuid, data):
        return {**_FAKE_USER, **{k: v for k, v in data.items()}}

    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1.UsersDAO, "find_duplicate_student_exclude_self", fake_find_dup)
    monkeypatch.setattr(users_v1.UsersDAO, "update", fake_update, raising=False)

    response = profile_client.patch(
        "/api/v1/users/me/profile",
        json={"real_name": "李小明", "class": "高二(2)班"},
    )
    assert response.status_code == 200
    assert response.json()["real_name"] == "李小明"
    assert response.json()["class"] == "高二(2)班"


def test_update_profile_returns_409_on_duplicate(profile_client, monkeypatch):
    """修改姓名和班级后与其他用户冲突时返回 409。"""

    async def fake_find_dup(session, real_name, class_, exclude_uuid):
        return SimpleNamespace(uuid="other-uuid")  # 冲突

    monkeypatch.setattr(users_v1, "get_session", _mock_get_session())
    monkeypatch.setattr(users_v1.UsersDAO, "find_duplicate_student_exclude_self", fake_find_dup)

    response = profile_client.patch(
        "/api/v1/users/me/profile",
        json={"real_name": "张三", "class": "高一(1)班"},
    )
    assert response.status_code == 409
    assert "已存在" in response.json()["detail"]


def test_update_profile_returns_422_when_no_fields(profile_client):
    """不提供任何修改字段时返回 422。"""
    response = profile_client.patch("/api/v1/users/me/profile", json={})
    assert response.status_code == 422


def test_update_profile_returns_422_when_control_char_in_nickname(profile_client):
    """nickname 包含控制字符时返回 422。"""
    response = profile_client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "bad\x01name"},
    )
    assert response.status_code == 422


def test_update_profile_returns_403_when_account_banned(monkeypatch):
    """账号被封禁时返回 403。"""
    user_banned = {**_FAKE_USER, "current_status": "banned"}
    app = FastAPI()
    app.include_router(users_v1.router, prefix="/api/v1")
    app.dependency_overrides[users_v1.get_current_user] = lambda: user_banned
    client = TestClient(app)

    response = client.patch(
        "/api/v1/users/me/profile",
        json={"nickname": "新昵称"},
    )
    assert response.status_code == 403
    assert "账号状态异常" in response.json()["detail"]
