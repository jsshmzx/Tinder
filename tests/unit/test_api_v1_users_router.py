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
