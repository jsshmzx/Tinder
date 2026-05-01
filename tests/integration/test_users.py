"""Integration tests — User registration endpoints with real PostgreSQL + Redis backend.

Covers:
  * GET  /api/v1/users/register/questions — question sheet generation
  * POST /api/v1/users/register           — full registration flow

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

# Redis key prefixes used by the registration module (mirror constants in users.py)
_REG_KEY_PREFIXES = ("reg:qsheet:", "reg:qsheet_atm:", "reg:ip_atm:", "reg:name_atm:", "reg:ip_sheets:")


def _flush_reg_keys(redis_client) -> None:
    """删除 Redis 中所有以 'reg:' 开头的注册相关键，使每个测试从干净状态开始。"""
    for key in redis_client.scan_iter("reg:*"):
        redis_client.delete(key)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def active_questions(db_session_factory):
    """在 register_questions 表中插入 5 道 active 测试题目，测试后清理。"""
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
    """每个测试前清除注册相关的 Redis 键，确保计数器独立。"""
    _flush_reg_keys(redis_client)
    yield
    _flush_reg_keys(redis_client)


@pytest.fixture
def registered_user_cleanup(db_session_factory):
    """收集在测试中注册的用户 uuid，并在测试后删除它们。"""
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
# GET /api/v1/users/register/questions
# ---------------------------------------------------------------------------


def test_get_questions_returns_sheet_id_and_five_questions(integration_client, active_questions):
    """成功获取问题表：返回 sheet_id 和 5 道不含答案的题目。"""
    print("\n[TEST][Users] GET /api/v1/users/register/questions → 应返回 sheet_id 和 5 道题目")

    response = integration_client.get("/api/v1/users/register/questions")

    assert response.status_code == 200
    data = response.json()
    assert "sheet_id" in data
    assert isinstance(data["sheet_id"], str) and len(data["sheet_id"]) > 0
    assert len(data["questions"]) == 5
    for q in data["questions"]:
        assert "uuid" in q
        assert "question" in q
        assert "answer" not in q, "响应中不应包含答案"


def test_get_questions_stores_sheet_in_redis(integration_client, active_questions, redis_client):
    """问题表数据（含答案）应正确存入 Redis。"""
    print("\n[TEST][Users] GET /api/v1/users/register/questions → 问题表应存入 Redis")

    response = integration_client.get("/api/v1/users/register/questions")
    assert response.status_code == 200

    sheet_id = response.json()["sheet_id"]
    import json
    raw = redis_client.get(f"reg:qsheet:{sheet_id}")
    assert raw is not None, "Redis 中应存在问题表"

    sheet_data = json.loads(raw)
    assert "answers" in sheet_data
    assert len(sheet_data["answers"]) == 5


def test_get_questions_returns_503_when_no_active_questions(integration_client):
    """题库无 active 题目时应返回 503。"""
    print("\n[TEST][Users] GET /api/v1/users/register/questions → 无题目时应返回 503")

    # 不插入任何题目，直接请求
    response = integration_client.get("/api/v1/users/register/questions")
    assert response.status_code == 503


def test_get_questions_enforces_per_ip_daily_limit(integration_client, active_questions, redis_client):
    """IP 每日问题表申请次数达上限（4 次）后应返回 429。"""
    print("\n[TEST][Users] GET /api/v1/users/register/questions → IP 超限应返回 429")

    # 预置 Redis 计数器至上限
    from datetime import date
    today = date.today().isoformat()
    redis_client.set(f"reg:ip_sheets:testclient:{today}", 4)

    response = integration_client.get("/api/v1/users/register/questions")
    assert response.status_code == 429


# ---------------------------------------------------------------------------
# POST /api/v1/users/register
# ---------------------------------------------------------------------------


def _get_sheet(integration_client, active_questions):
    """辅助：先获取一张问题表，返回 (sheet_id, questions)。"""
    resp = integration_client.get("/api/v1/users/register/questions")
    assert resp.status_code == 200, f"获取问题表失败: {resp.text}"
    data = resp.json()
    return data["sheet_id"], data["questions"]


def _make_correct_answers(sheet_id: str, questions: list[dict], active_questions) -> list[dict]:
    """根据问题表中的题目 uuid，从 fixture 中找到正确答案并构建答案列表。"""
    uuid_to_answer = {q.uuid: q.answer for q in active_questions}
    return [
        {"question_uuid": q["uuid"], "answer": uuid_to_answer.get(q["uuid"], "wrong")}
        for q in questions
    ]


def test_register_success_with_correct_answers(
    integration_client, active_questions, registered_user_cleanup
):
    """答题全对、无重复学生 → 注册成功，返回 201 + access_token + 用户信息。"""
    print("\n[TEST][Users] POST /api/v1/users/register → 正常注册应返回 201 和 token")

    sheet_id, questions = _get_sheet(integration_client, active_questions)
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
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["real_name"] == "王小明"
    assert data["user"]["role"] == "normal-user"
    assert data["user"]["is_verified"] is False
    assert data["user"]["status"] == "normal"
    assert len(data["access_token"]) > 0

    registered_user_cleanup.append(data["user"]["uuid"])


def test_register_user_fields_persisted_in_database(
    integration_client, active_questions, db_session_factory, registered_user_cleanup
):
    """注册成功后，用户数据应正确持久化到数据库。"""
    print("\n[TEST][Users] POST /api/v1/users/register → 用户数据应写入数据库")

    sheet_id, questions = _get_sheet(integration_client, active_questions)
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
    """所有答案错误时（答对 0 道）应返回 400。"""
    print("\n[TEST][Users] POST /api/v1/users/register → 答案全错应返回 400")

    sheet_id, questions = _get_sheet(integration_client, active_questions)
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
    """恰好答对 3 道应通过（≥ 3 道即可）。"""
    print("\n[TEST][Users] POST /api/v1/users/register → 答对 3 道应通过")

    sheet_id, questions = _get_sheet(integration_client, active_questions)
    uuid_to_answer = {q.uuid: q.answer for q in active_questions}

    # 前 3 道答对，后 2 道答错
    answers = []
    for i, q in enumerate(questions):
        if i < 3:
            answers.append({"question_uuid": q["uuid"], "answer": uuid_to_answer.get(q["uuid"], "wrong")})
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
    """答案校验应大小写不敏感。"""
    print("\n[TEST][Users] POST /api/v1/users/register → 答案大小写不敏感")

    sheet_id, questions = _get_sheet(integration_client, active_questions)
    uuid_to_answer = {q.uuid: q.answer for q in active_questions}

    # 将正确答案全部转为大写提交
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
    """不存在的 sheet_id 应返回 400。"""
    print("\n[TEST][Users] POST /api/v1/users/register → 无效 sheet_id 应返回 400")

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
    integration_client, active_questions, registered_user_cleanup
):
    """相同 real_name + class 重复注册时应返回 409。"""
    print("\n[TEST][Users] POST /api/v1/users/register → 重复学生应返回 409")

    # 第一次注册
    sheet_id, questions = _get_sheet(integration_client, active_questions)
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

    # 第二次注册（相同 real_name + class）
    _flush_reg_keys(integration_client.app.state.__dict__.get("redis", None) or __import__("redis").from_url(
        __import__("os").environ["REDIS_URL"], decode_responses=True
    ))
    sheet_id2, questions2 = _get_sheet(integration_client, active_questions)
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
    """IP 当日注册尝试次数达上限（10 次）后应返回 429。"""
    print("\n[TEST][Users] POST /api/v1/users/register → IP 超 10 次限制应返回 429")

    from datetime import date
    today = date.today().isoformat()
    redis_client.set(f"reg:ip_atm:testclient:{today}", 10)

    sheet_id, questions = _get_sheet(integration_client, active_questions)
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
    """同一 real_name 当日尝试次数达上限（3 次）后应返回 429。"""
    print("\n[TEST][Users] POST /api/v1/users/register → real_name 超 3 次限制应返回 429")

    from datetime import date
    real_name = "名字限制测试"
    name_hex = real_name.encode("utf-8").hex()
    today = date.today().isoformat()
    redis_client.set(f"reg:name_atm:{name_hex}:{today}", 3)

    sheet_id, questions = _get_sheet(integration_client, active_questions)
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
    """同一问题表尝试次数达上限（3 次）后应返回 400。"""
    print("\n[TEST][Users] POST /api/v1/users/register → 问题表超 3 次限制应返回 400")

    sheet_id, questions = _get_sheet(integration_client, active_questions)
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
    """classtype 不合法（非 high-school / university）时应返回 422。"""
    print("\n[TEST][Users] POST /api/v1/users/register → 非法 classtype 应返回 422")

    sheet_id, questions = _get_sheet(integration_client, active_questions)
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
    """注册成功后问题表应从 Redis 中删除（防止重用）。"""
    print("\n[TEST][Users] POST /api/v1/users/register → 成功后问题表应从 Redis 删除")

    sheet_id, questions = _get_sheet(integration_client, active_questions)
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

    # 问题表应已从 Redis 删除
    assert redis_client.get(f"reg:qsheet:{sheet_id}") is None
