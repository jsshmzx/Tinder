"""Integration tests — User registration endpoints with real PostgreSQL + Redis backend.

Covers:
  * POST /api/v1/users/register/sheet/request — question sheet generation
  * POST /api/v1/users/register              — full registration flow

All tests use real DB & Redis (see conftest.py).
Redis register-namespace keys are flushed before each test to ensure isolation.
"""

import uuid as uuid_lib

import pytest

from core.database.dao.register_questions import RegisterQuestions
from core.database.dao.users import User


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REG_KEY_PREFIXES = ("reg:qsheet:", "reg:qsheet_atm:", "reg:ip_atm:", "reg:name_atm:", "reg:ip_sheets:")


def _flush_reg_keys(redis_client) -> None:
    """Delete all Redis keys with 'reg:' prefix so each test starts clean."""
    for key in redis_client.scan_iter("reg:*"):
        redis_client.delete(key)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def active_questions(db_session_factory):
    """Insert 5 active questions into register_questions table, clean up after."""
    session = db_session_factory()

    questions = [
        RegisterQuestions(
            uuid=str(uuid_lib.uuid4()),
            question=f"测试题目 {i}",
            answer=f"answer{i}",
            current_status="active",
        )
        for i in range(1, 6)
    ]
    for q in questions:
        session.add(q)
    session.commit()
    for q in questions:
        session.refresh(q)

    yield questions

    for q in questions:
        try:
            session.delete(q)
        except Exception:
            pass
    session.commit()
    session.close()


@pytest.fixture(autouse=True)
def flush_redis_before_each(redis_client):
    """Flush register-related Redis keys before each test for isolation."""
    _flush_reg_keys(redis_client)
    yield
    _flush_reg_keys(redis_client)


@pytest.fixture
def registered_user_cleanup(db_session_factory):
    """Collect user uuids created during tests and delete them after."""
    created_uuids: list[str] = []
    yield created_uuids
    if not created_uuids:
        return
    session = db_session_factory()
    for uid in created_uuids:
        user = session.query(User).filter_by(uuid=uid).first()
        if user:
            session.delete(user)
    session.commit()
    session.close()


# ---------------------------------------------------------------------------
# POST /api/v1/users/register/sheet/request
# ---------------------------------------------------------------------------


def _request_sheet(integration_client) -> tuple[str, list[dict]]:
    """Helper: request a question sheet and return (sheet_id, questions)."""
    resp = integration_client.post("/api/v1/users/register/sheet/request")
    assert resp.status_code == 200, f"Sheet request failed: {resp.text}"
    data = resp.json()
    return data["sheet_id"], data["questions"]


def test_get_questions_returns_sheet_id_and_five_questions(integration_client, active_questions):
    """Requesting a sheet should return a sheet_id and 5 questions without answers."""
    sheet_id, questions = _request_sheet(integration_client)

    assert isinstance(sheet_id, str) and len(sheet_id) > 0
    assert len(questions) == 5
    for q in questions:
        assert "uuid" in q
        assert "question" in q
        assert "answer" not in q, "Responses must not include answers"


def test_get_questions_stores_sheet_in_redis(integration_client, active_questions, redis_client):
    """Question sheet data (with answers) should be stored in Redis."""
    sheet_id, _ = _request_sheet(integration_client)

    import json
    raw = redis_client.get(f"reg:qsheet:{sheet_id}")
    assert raw is not None, "Redis should contain the question sheet"

    sheet_data = json.loads(raw)
    assert "answers" in sheet_data
    assert len(sheet_data["answers"]) == 5


def test_get_questions_returns_503_when_no_active_questions(integration_client):
    """When no active questions exist, should return 503."""
    # Do not insert any questions
    response = integration_client.post("/api/v1/users/register/sheet/request")
    assert response.status_code == 503


def test_get_questions_enforces_per_ip_daily_limit(integration_client, active_questions, redis_client):
    """IP daily sheet request limit (4/day) should return 429 when exceeded."""
    from datetime import date
    today = date.today().isoformat()
    redis_client.set(f"reg:ip_sheets:testclient:{today}", 4)

    response = integration_client.post("/api/v1/users/register/sheet/request")
    assert response.status_code == 429


# ---------------------------------------------------------------------------
# POST /api/v1/users/register
# ---------------------------------------------------------------------------


def _make_correct_answers(sheet_id: str, questions: list[dict], active_questions) -> list[dict]:
    """Build answer list with correct answers from the active_questions fixture."""
    uuid_to_answer = {q.uuid: q.answer for q in active_questions}
    return [
        {"question_uuid": q["uuid"], "answer": uuid_to_answer.get(q["uuid"], "wrong")}
        for q in questions
    ]


def test_register_success_with_correct_answers(
    integration_client, active_questions, registered_user_cleanup
):
    """All answers correct, no duplicate student → 201 with user info."""
    sheet_id, questions = _request_sheet(integration_client)
    answers = _make_correct_answers(sheet_id, questions, active_questions)

    response = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "测试用户",
            "real_name": "王小明",
            "classtype": "high-school",
            "class": "高一(1)班",
            "sheet_id": sheet_id,
            "answers": answers,
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert "temp_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["real_name"] == "王小明"
    assert data["user"]["role"] == "normal-user"
    assert data["user"]["is_verified"] is False
    assert data["user"]["status"] == "normal"
    assert len(data["temp_token"]) > 0

    registered_user_cleanup.append(data["user"]["uuid"])


def test_register_user_fields_persisted_in_database(
    integration_client, active_questions, db_session_factory, registered_user_cleanup
):
    """Registered user data should be persisted in the database."""
    sheet_id, questions = _request_sheet(integration_client)
    answers = _make_correct_answers(sheet_id, questions, active_questions)

    response = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "数据库测试",
            "real_name": "李数据",
            "classtype": "university",
            "class": "计科1班",
            "sheet_id": sheet_id,
            "answers": answers,
        },
    )
    assert response.status_code == 201
    new_uuid = response.json()["user"]["uuid"]
    registered_user_cleanup.append(new_uuid)

    session = db_session_factory()
    user = session.query(User).filter_by(uuid=new_uuid).first()
    session.close()

    assert user is not None
    assert user.nickname == "数据库测试"
    assert user.real_name == "李数据"
    assert user.class_ == "计科1班"
    assert user.class_type == "university"
    assert user.user_role == "normal-user"
    assert user.is_verified is False
    assert user.current_status == "normal"


def test_register_fails_with_wrong_answers(integration_client, active_questions):
    """All wrong answers (0 correct) should return 400."""
    sheet_id, questions = _request_sheet(integration_client)
    wrong_answers = [
        {"question_uuid": q["uuid"], "answer": "完全错误的答案xyz"}
        for q in questions
    ]

    response = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "失败用户",
            "real_name": "错误答案君",
            "classtype": "high-school",
            "class": "高一(2)班",
            "sheet_id": sheet_id,
            "answers": wrong_answers,
        },
    )

    assert response.status_code == 400
    assert "答题未通过" in response.json()["detail"]


def test_register_passes_with_exactly_three_correct(
    integration_client, active_questions, registered_user_cleanup
):
    """Exactly 3 correct answers should pass (threshold is >= 3)."""
    sheet_id, questions = _request_sheet(integration_client)
    uuid_to_answer = {q.uuid: q.answer for q in active_questions}

    # First 3 correct, last 2 wrong
    answers = []
    for i, q in enumerate(questions):
        if i < 3:
            answers.append({
                "question_uuid": q["uuid"],
                "answer": uuid_to_answer.get(q["uuid"], "wrong"),
            })
        else:
            answers.append({"question_uuid": q["uuid"], "answer": "wrong_answer_xyz"})

    response = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "三对用户",
            "real_name": "三对测试",
            "classtype": "university",
            "class": "英语2班",
            "sheet_id": sheet_id,
            "answers": answers,
        },
    )

    assert response.status_code == 201
    registered_user_cleanup.append(response.json()["user"]["uuid"])


def test_register_answers_are_case_insensitive(
    integration_client, active_questions, registered_user_cleanup
):
    """Answer matching should be case-insensitive."""
    sheet_id, questions = _request_sheet(integration_client)
    uuid_to_answer = {q.uuid: q.answer for q in active_questions}

    # Submit all answers in uppercase
    answers = [
        {"question_uuid": q["uuid"], "answer": uuid_to_answer.get(q["uuid"], "wrong").upper()}
        for q in questions
    ]

    response = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "大写用户",
            "real_name": "大写测试员",
            "classtype": "high-school",
            "class": "高二(3)班",
            "sheet_id": sheet_id,
            "answers": answers,
        },
    )

    assert response.status_code == 201
    registered_user_cleanup.append(response.json()["user"]["uuid"])


def test_register_fails_with_nonexistent_sheet(integration_client, active_questions):
    """Non-existent sheet_id should return 400."""
    response = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "假表用户",
            "real_name": "假表测试",
            "classtype": "university",
            "class": "物理1班",
            "sheet_id": "nonexistent-sheet-id-xyz",
            "answers": [
                {"question_uuid": f"q-{i}", "answer": f"ans{i}"}
                for i in range(1, 6)
            ],
        },
    )

    assert response.status_code == 400
    assert "问题表" in response.json()["detail"]


def test_register_fails_on_duplicate_student(
    integration_client, active_questions, registered_user_cleanup, redis_client
):
    """Same real_name + class registered twice should return 409 on the second attempt."""
    # First registration
    sheet_id, questions = _request_sheet(integration_client)
    answers = _make_correct_answers(sheet_id, questions, active_questions)

    resp1 = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "原始用户",
            "real_name": "重复姓名",
            "classtype": "high-school",
            "class": "高三(1)班",
            "sheet_id": sheet_id,
            "answers": answers,
        },
    )
    assert resp1.status_code == 201
    registered_user_cleanup.append(resp1.json()["user"]["uuid"])

    # Flush rate-limit counters to allow the second request past throttling
    _flush_reg_keys(redis_client)

    # Second registration (same real_name + class)
    sheet_id2, questions2 = _request_sheet(integration_client)
    answers2 = _make_correct_answers(sheet_id2, questions2, active_questions)

    resp2 = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "重复用户",
            "real_name": "重复姓名",
            "classtype": "high-school",
            "class": "高三(1)班",
            "sheet_id": sheet_id2,
            "answers": answers2,
        },
    )
    assert resp2.status_code == 409
    assert "已存在" in resp2.json()["detail"]


def test_register_enforces_ip_daily_limit(integration_client, active_questions, redis_client):
    """IP daily registration attempt limit (10/day) should return 429."""
    from datetime import date
    today = date.today().isoformat()
    redis_client.set(f"reg:ip_atm:testclient:{today}", 10)

    sheet_id, questions = _request_sheet(integration_client)
    answers = _make_correct_answers(sheet_id, questions, active_questions)

    response = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "被限制用户",
            "real_name": "被限制",
            "classtype": "university",
            "class": "信息1班",
            "sheet_id": sheet_id,
            "answers": answers,
        },
    )
    assert response.status_code == 429
    assert "IP" in response.json()["detail"]


def test_register_enforces_name_daily_limit(integration_client, active_questions, redis_client):
    """Same real_name daily limit (3/day) should return 429."""
    from datetime import date
    real_name = "名字限制测试"
    name_hex = real_name.encode("utf-8").hex()
    today = date.today().isoformat()
    redis_client.set(f"reg:name_atm:{name_hex}:{today}", 3)

    sheet_id, questions = _request_sheet(integration_client)
    answers = _make_correct_answers(sheet_id, questions, active_questions)

    response = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "名字超限",
            "real_name": real_name,
            "classtype": "high-school",
            "class": "高一(5)班",
            "sheet_id": sheet_id,
            "answers": answers,
        },
    )
    assert response.status_code == 429
    assert "姓名" in response.json()["detail"]


def test_register_enforces_sheet_attempt_limit(integration_client, active_questions, redis_client):
    """Same sheet exceeding max attempts (3) should return 400."""
    sheet_id, questions = _request_sheet(integration_client)
    redis_client.set(f"reg:qsheet_atm:{sheet_id}", 3)

    wrong_answers = [
        {"question_uuid": q["uuid"], "answer": "wrong"}
        for q in questions
    ]

    response = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "超限用户",
            "real_name": "问题表超限",
            "classtype": "university",
            "class": "数学3班",
            "sheet_id": sheet_id,
            "answers": wrong_answers,
        },
    )
    assert response.status_code == 400
    assert "尝试次数已达上限" in response.json()["detail"]


def test_register_rejects_invalid_classtype(integration_client, active_questions):
    """Invalid classtype should return 422."""
    sheet_id, questions = _request_sheet(integration_client)
    answers = _make_correct_answers(sheet_id, questions, active_questions)

    response = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "非法学段",
            "real_name": "非法学段测试",
            "classtype": "kindergarten",
            "class": "小班",
            "sheet_id": sheet_id,
            "answers": answers,
        },
    )
    assert response.status_code == 422


def test_register_sheet_deleted_from_redis_after_success(
    integration_client, active_questions, redis_client, registered_user_cleanup
):
    """Question sheet should be removed from Redis after successful registration."""
    sheet_id, questions = _request_sheet(integration_client)
    answers = _make_correct_answers(sheet_id, questions, active_questions)

    response = integration_client.post(
        "/api/v1/users/register",
        json={
            "nickname": "清理测试",
            "real_name": "Redis清理测试",
            "classtype": "high-school",
            "class": "高一(6)班",
            "sheet_id": sheet_id,
            "answers": answers,
        },
    )
    assert response.status_code == 201
    registered_user_cleanup.append(response.json()["user"]["uuid"])

    # Sheet should be deleted from Redis
    assert redis_client.get(f"reg:qsheet:{sheet_id}") is None
