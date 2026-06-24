"""Unit tests — modules.api.v1.admin /admin/questions endpoints (no database, no Redis)."""

import json
import uuid as uuid_lib
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from modules.api.v1.admin import router as admin_router


@pytest.fixture()
def client():
    app = FastAPI()
    app.include_router(admin_router)
    # Override auth dependencies to always pass for superadmin
    from core.middleware.auth.dependencies import MinRoleChecker, get_current_user
    from core.security.rbac import Role
    app.dependency_overrides[MinRoleChecker(Role.SUPERADMIN.value)] = lambda: {"uuid": "admin-uuid"}
    app.dependency_overrides[get_current_user] = lambda: {"uuid": "admin-uuid", "user_role": "superadmin"}
    return TestClient(app)


def test_list_questions_returns_paginated_results(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    fake_questions = [
        {"uuid": "q-1", "question": "Test?", "question_type": "choice", "answer": "A",
         "options": json.dumps(["A", "B"]), "question_level": "easy", "current_status": "active",
         "created_by": "admin", "created_at": "2025-01-01T00:00:00", "id": 1},
    ]

    async def fake_search(keyword=None, question_type=None, status=None, limit=100, offset=0):
        return fake_questions

    async def fake_count(keyword=None, question_type=None, status=None):
        return 1

    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "search_questions", fake_search)
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "count_questions", fake_count)

    response = client.get("/admin/questions?limit=20&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["uuid"] == "q-1"


def test_list_questions_supports_filters(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    captured = {}

    async def fake_search(keyword=None, question_type=None, status=None, limit=100, offset=0):
        captured.update(keyword=keyword, question_type=question_type, status=status)
        return []

    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "search_questions", fake_search)

    response = client.get("/admin/questions?keyword=test&type=choice&status=active")
    assert response.status_code == 200
    assert captured["keyword"] == "test"
    assert captured["question_type"] == "choice"
    assert captured["status"] == "active"


def test_questions_total(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    async def fake_count(keyword=None, question_type=None, status=None):
        return 42
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "count_questions", fake_count)
    response = client.get("/admin/questions/total")
    assert response.status_code == 200
    assert response.json() == {"total": 42}


def test_create_question_choice(client, monkeypatch):
    from modules.api.v1 import admin as admin_module

    created = {}

    async def fake_create(data):
        data["uuid"] = str(uuid_lib.uuid4())
        data["id"] = 1
        created.update(data)
        return data

    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "create", fake_create)

    payload = {
        "question": "以下哪个是中国首都？",
        "question_type": "choice",
        "answer": "北京",
        "options": ["北京", "上海", "广州", "深圳"],
        "question_level": "easy",
    }
    response = client.post("/admin/questions", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["question"] == "以下哪个是中国首都？"
    assert created.get("current_status") == "active"
    assert created.get("created_by") == "admin-uuid"


def test_create_question_choice_invalid_answer_not_in_options(client, monkeypatch):
    from modules.api.v1 import admin as admin_module

    payload = {
        "question": "测试？",
        "question_type": "choice",
        "answer": "不在选项中的答案",
        "options": ["A", "B"],
    }
    response = client.post("/admin/questions", json=payload)
    assert response.status_code == 422


def test_create_question_choice_less_than_2_options(client, monkeypatch):
    from modules.api.v1 import admin as admin_module

    payload = {
        "question": "测试？",
        "question_type": "choice",
        "answer": "A",
        "options": ["A"],
    }
    response = client.post("/admin/questions", json=payload)
    assert response.status_code == 422


def test_create_question_true_false_valid(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    created = {}
    async def fake_create(data):
        data["uuid"] = str(uuid_lib.uuid4())
        data["id"] = 1
        created.update(data)
        return data
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "create", fake_create)

    for answer in ("true", "false"):
        response = client.post("/admin/questions", json={
            "question": "地球是圆的",
            "question_type": "true_false",
            "answer": answer,
        })
        assert response.status_code == 201


def test_create_question_true_false_invalid_answer(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    response = client.post("/admin/questions", json={
        "question": "测试",
        "question_type": "true_false",
        "answer": "maybe",
    })
    assert response.status_code == 422


def test_create_question_fill_blank(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    created = {}
    async def fake_create(data):
        data["uuid"] = str(uuid_lib.uuid4())
        data["id"] = 1
        created.update(data)
        return data
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "create", fake_create)

    response = client.post("/admin/questions", json={
        "question": "中国的首都是____",
        "question_type": "fill_blank",
        "answer": "北京",
    })
    assert response.status_code == 201
    assert "options" not in created or created.get("options") is None


def test_update_question(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    updated = {}
    async def fake_find_by_uuid(self, uuid):
        return {"uuid": uuid, "question_type": "choice"}
    async def fake_update(self, uuid, data):
        updated.update(data)
        updated["uuid"] = uuid
        return updated
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "find_by_uuid", fake_find_by_uuid, raising=False)
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "update", fake_update, raising=False)

    response = client.patch("/admin/questions/q-1", json={"question": "修改后的题目？", "answer": "B", "options": ["A", "B"]})
    assert response.status_code == 200
    assert updated["question"] == "修改后的题目？"


def test_update_nonexistent_question_returns_404(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    async def fake_find_by_uuid(self, uuid):
        return None
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "find_by_uuid", fake_find_by_uuid, raising=False)
    response = client.patch("/admin/questions/nonexistent", json={"question": "测试"})
    assert response.status_code == 404


def test_delete_question(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    deleted = []
    async def fake_delete(self, uuid):
        deleted.append(uuid)
        return True
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "delete", fake_delete, raising=False)
    response = client.delete("/admin/questions/q-1")
    assert response.status_code == 200
    assert "q-1" in deleted


def test_delete_question_not_found(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    async def fake_delete(self, uuid):
        return False
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "delete", fake_delete, raising=False)
    response = client.delete("/admin/questions/nonexistent")
    assert response.status_code == 404


def test_batch_delete_questions(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    captured = []
    async def fake_batch_delete(uuids):
        captured.extend(uuids)
        return len(uuids)
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "batch_delete_by_uuids", fake_batch_delete)
    response = client.post("/admin/questions/batch-delete", json={"uuids": ["q-1", "q-2"]})
    assert response.status_code == 200
    assert response.json() == {"deleted": 2}
    assert captured == ["q-1", "q-2"]


def test_batch_update_status(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    captured = {}
    async def fake_batch_update(uuids, status):
        captured["uuids"] = uuids
        captured["status"] = status
        return len(uuids)
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "batch_update_status", fake_batch_update)
    response = client.patch("/admin/questions/batch-status", json={"uuids": ["q-1", "q-2"], "status": "inactive"})
    assert response.status_code == 200
    assert response.json() == {"updated": 2}
    assert captured["status"] == "inactive"


def test_single_update_status(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    captured = {}
    async def fake_update(self, uuid, data):
        captured["uuid"] = uuid
        captured["status"] = data.get("current_status")
        return captured
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "update", fake_update, raising=False)
    response = client.patch("/admin/questions/q-1/status", json={"status": "inactive"})
    assert response.status_code == 200
    assert captured["uuid"] == "q-1"
    assert captured["status"] == "inactive"


def test_questions_stats(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    async def fake_count_by_type(t):
        return {"choice": 10, "true_false": 5, "fill_blank": 3}.get(t, 0)
    async def fake_count(keyword=None, question_type=None, status=None):
        return 18
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "count_by_type", fake_count_by_type)
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "count_questions", fake_count)
    response = client.get("/admin/questions/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 18
    assert data["choice"] == 10
    assert data["true_false"] == 5
    assert data["fill_blank"] == 3


def test_create_question_choice_rejects_duplicate_options(client, monkeypatch):
    payload = {
        "question": "测试？",
        "question_type": "choice",
        "answer": "A",
        "options": ["A", "A", "B"],
    }
    response = client.post("/admin/questions", json=payload)
    assert response.status_code == 422


def test_update_question_true_false_validates_answer(client, monkeypatch):
    from modules.api.v1 import admin as admin_module

    async def fake_find_by_uuid(self, uuid):
        return {"uuid": uuid, "question_type": "true_false"}

    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    response = client.patch(
        "/admin/questions/q-1",
        json={"answer": "maybe"},
    )
    assert response.status_code == 400
    assert "判断题" in response.json()["detail"]


def test_update_question_at_least_one_field(client, monkeypatch):
    from modules.api.v1 import admin as admin_module

    async def fake_find_by_uuid(self, uuid):
        return {"uuid": uuid, "question_type": "choice"}

    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    response = client.patch(
        "/admin/questions/q-1",
        json={},
    )
    assert response.status_code == 422


def test_update_question_choice_answer_not_in_options(client, monkeypatch):
    from modules.api.v1 import admin as admin_module

    async def fake_find_by_uuid(self, uuid):
        return {"uuid": uuid, "question_type": "choice"}

    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "find_by_uuid", fake_find_by_uuid, raising=False)

    response = client.patch(
        "/admin/questions/q-1",
        json={"answer": "C", "options": ["A", "B"]},
    )
    assert response.status_code == 400
    assert "答案必须在选项中" in response.json()["detail"]
