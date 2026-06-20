# 注册问题管理功能 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为管理员添加注册问题的 CRUD + 批量管理能力，包括后端 API 和前端管理页面。

**Architecture:** Tinder 后端在现有 `admin.py` 路由中追加注册问题管理端点，扩展 `RegisterQuestionsDAO` 以支持分页搜索、计数、批量操作。NavisBridge 前端新增 `RegisterQuestions` 页面，遵循 `UserManage` 的 ProTable + Ant Design 模式。

**Tech Stack:** FastAPI / SQLAlchemy / UmiJS 4 / Ant Design 5 / ProComponents

## Global Constraints

- 所有后端 API 接口需要 superadmin 角色（`MinRoleChecker(Role.SUPERADMIN.value)`）
- 删除/批量操作无需超级密码
- 校验逻辑：`answer` 统一 `strip().lower()` 后精确字符串比对
- 选择题 `options` 字段存储 JSON 数组字符串，非选择题为 NULL
- 前端使用 `ProTable` + `PageContainer`，风格与 `UserManage` 保持一致
- 所有新增前端的列、标签文案使用中文

---

### Task 1: 数据库迁移 + ORM 模型更新

**Files:**
- Create: `core/database/migrations/SQL/alter_register_questions_add_options.sql`
- Modify: `core/database/migrations/migration_history.py`
- Modify: `core/database/dao/register_questions.py`

**Interfaces:**
- Consumes: 现有 `RegisterQuestions` ORM 模型、`migration_history` 列表
- Produces: 数据库中有 `options` 列的 `register_questions` 表；ORM 模型新增 `options` 属性

- [ ] **Step 1: 创建迁移 SQL 文件**

写入 `core/database/migrations/SQL/alter_register_questions_add_options.sql`：

```sql
ALTER TABLE register_questions
  ADD COLUMN IF NOT EXISTS options TEXT;
```

- [ ] **Step 2: 追加到迁移历史列表**

编辑 `core/database/migrations/migration_history.py`，在末尾追加：

```python
migration_history = [
    # ... 现有列表 ...
    "alter_register_questions_add_options.sql",
]
```

- [ ] **Step 3: 更新 ORM 模型**

编辑 `core/database/dao/register_questions.py`，在 `RegisterQuestions` 类中新增 `options` 字段：

在 `answer: Mapped[str]` 行之后添加：
```python
    options: Mapped[str | None] = mapped_column(Text)
```

- [ ] **Step 4: 扩展 DAO 方法**

在 `RegisterQuestionsDAO` 类中追加方法：

```python
    @staticmethod
    async def search_questions(
        keyword: str | None = None,
        question_type: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """分页搜索题目，支持 keyword 模糊匹配 question，type/status 精确筛选。"""
        from sqlalchemy import or_
        async with get_session() as session:
            stmt = select(RegisterQuestions)
            conditions = []
            if keyword:
                conditions.append(RegisterQuestions.question.ilike(f"%{keyword}%"))
            if question_type:
                conditions.append(RegisterQuestions.question_type == question_type)
            if status:
                conditions.append(RegisterQuestions.current_status == status)
            if conditions:
                stmt = stmt.where(*conditions)
            objs = await session.scalars(
                stmt.order_by(RegisterQuestions.id.desc()).limit(limit).offset(offset)
            )
            return [RegisterQuestionsDAO._to_dict(o) for o in objs]

    @staticmethod
    async def count_questions(
        keyword: str | None = None,
        question_type: str | None = None,
        status: str | None = None,
    ) -> int:
        """按条件统计题目总数。"""
        from sqlalchemy import func
        async with get_session() as session:
            stmt = select(func.count(RegisterQuestions.id))
            conditions = []
            if keyword:
                conditions.append(RegisterQuestions.question.ilike(f"%{keyword}%"))
            if question_type:
                conditions.append(RegisterQuestions.question_type == question_type)
            if status:
                conditions.append(RegisterQuestions.current_status == status)
            if conditions:
                stmt = stmt.where(*conditions)
            result = await session.execute(stmt)
            return result.scalar() or 0

    @staticmethod
    async def count_by_type(question_type: str) -> int:
        """按题型统计题目数。"""
        from sqlalchemy import func
        async with get_session() as session:
            result = await session.execute(
                select(func.count(RegisterQuestions.id))
                .where(RegisterQuestions.question_type == question_type)
            )
            return result.scalar() or 0

    @staticmethod
    async def batch_delete_by_uuids(uuids: list[str]) -> int:
        """批量删除题目，返回实际删除数量。"""
        async with get_session() as session:
            result = await session.execute(
                RegisterQuestions.__table__.delete().where(RegisterQuestions.uuid.in_(uuids))
            )
            return result.rowcount

    @staticmethod
    async def batch_update_status(uuids: list[str], status: str) -> int:
        """批量更新题目状态，返回实际更新数量。"""
        async with get_session() as session:
            result = await session.execute(
                RegisterQuestions.__table__.update()
                .where(RegisterQuestions.uuid.in_(uuids))
                .values(current_status=status)
            )
            return result.rowcount
```

- [ ] **Step 5: 提交**

```bash
git -C /Users/huangtianrui/Documents/Project/jsshmzx/Tinder add core/database/migrations/SQL/alter_register_questions_add_options.sql core/database/migrations/migration_history.py core/database/dao/register_questions.py
git -C /Users/huangtianrui/Documents/Project/jsshmzx/Tinder commit -m "feat(db): add options column to register_questions and extend DAO"
```

---

### Task 2: 后端 API 路由

**Files:**
- Create: `tests/unit/test_api_v1_admin_questions.py`
- Modify: `modules/api/v1/admin.py`

**Interfaces:**
- Consumes: `RegisterQuestionsDAO.search_questions`, `.count_questions`, `.count_by_type`, `.batch_delete_by_uuids`, `.batch_update_status`, `.find_by_uuid`, `.create`, `.update`
- Produces: 7 个 admin API 端点（GET/POST/PATCH/DELETE 操作题目）
- Test: 使用 mock 的 FastAPI `TestClient`（不依赖 DB/Redis）

- [ ] **Step 1: 编写测试文件**

创建 `tests/unit/test_api_v1_admin_questions.py`：

```python
"""Unit tests — modules.api.v1.admin /admin/questions endpoints (no database, no Redis)."""

import json
import uuid as uuid_lib
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from modules.api.v1.admin import router as admin_router


@pytest.fixture()
def client():
    app = FastAPI()
    app.include_router(admin_router)
    # Override MinRoleChecker to always pass for superadmin
    from core.middleware.auth.dependencies import MinRoleChecker
    from core.security.rbac import Role
    app.dependency_overrides[MinRoleChecker(Role.SUPERADMIN.value)] = lambda: {"uuid": "admin-uuid"}
    return TestClient(app)


# Helper: mock get_current_user
def _override_admin():
    return {"uuid": "admin-uuid", "user_role": "superadmin"}


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
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)

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
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)

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
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)
    response = client.get("/admin/questions/total")
    assert response.status_code == 200
    assert response.json() == {"total": 42}


def test_create_question_choice(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    import core.security.rbac as rbac_module

    created = {}

    async def fake_create(data):
        data["uuid"] = str(uuid_lib.uuid4())
        data["id"] = 1
        created.update(data)
        return data

    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "create", fake_create)
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)

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
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)

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
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)

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
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)

    for answer in ("true", "false"):
        response = client.post("/admin/questions", json={
            "question": "地球是圆的",
            "question_type": "true_false",
            "answer": answer,
        })
        assert response.status_code == 201


def test_create_question_true_false_invalid_answer(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)
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
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)

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
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)

    response = client.patch("/admin/questions/q-1", json={"question": "修改后的题目？", "answer": "B", "options": ["A", "B"]})
    assert response.status_code == 200
    assert updated["question"] == "修改后的题目？"


def test_update_nonexistent_question_returns_404(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    async def fake_find_by_uuid(self, uuid):
        return None
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "find_by_uuid", fake_find_by_uuid, raising=False)
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)
    response = client.patch("/admin/questions/nonexistent", json={"question": "测试"})
    assert response.status_code == 404


def test_delete_question(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    deleted = []
    async def fake_delete(self, uuid):
        deleted.append(uuid)
        return True
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "delete", fake_delete, raising=False)
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)
    response = client.delete("/admin/questions/q-1")
    assert response.status_code == 200
    assert "q-1" in deleted


def test_delete_question_not_found(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    async def fake_delete(self, uuid):
        return False
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "delete", fake_delete, raising=False)
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)
    response = client.delete("/admin/questions/nonexistent")
    assert response.status_code == 404


def test_batch_delete_questions(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    captured = []
    async def fake_batch_delete(uuids):
        captured.extend(uuids)
        return len(uuids)
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "batch_delete_by_uuids", fake_batch_delete)
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)
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
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)
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
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)
    response = client.patch("/admin/questions/q-1/status", json={"status": "inactive"})
    assert response.status_code == 200


def test_questions_stats(client, monkeypatch):
    from modules.api.v1 import admin as admin_module
    async def fake_count_by_type(t):
        return {"choice": 10, "true_false": 5, "fill_blank": 3}.get(t, 0)
    async def fake_count(keyword=None, question_type=None, status=None):
        return 18
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "count_by_type", fake_count_by_type)
    monkeypatch.setattr(admin_module.RegisterQuestionsDAO, "count_questions", fake_count)
    monkeypatch.setattr(admin_module, "get_current_user", _override_admin)
    response = client.get("/admin/questions/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 18
    assert data["choice"] == 10
    assert data["true_false"] == 5
    assert data["fill_blank"] == 3
```

- [ ] **Step 2: 运行测试验证失败**

```bash
cd /Users/huangtianrui/Documents/Project/jsshmzx/Tinder && python -m pytest tests/unit/test_api_v1_admin_questions.py --tb=short 2>&1 | head -30
```
Expected: ModuleNotFoundError / ImportError — 因为路由尚未实现。

- [ ] **Step 3: 实现 API 路由**

在 `modules/api/v1/admin.py` 末尾追加（注意：这些路由通过 admin.py 中已存在的 `router` 对象注册，需要确保在 `Modules/api/v1/admin.py` 开始处有 `from core.database.dao.register_questions import RegisterQuestionsDAO`）：

先在文件顶部追加 import：
```python
import uuid as uuid_lib
import json
# ... 现有 imports ...
from core.database.dao.register_questions import RegisterQuestionsDAO
```

然后在文件末尾添加 Pydantic 模型和路由：

```python
# =========================================================================
# 注册问题管理
# =========================================================================

class QuestionCreateRequest(BaseModel):
    """创建题目请求体。"""
    question: str = Field(..., min_length=1, max_length=500, description="题目内容")
    question_type: Literal["choice", "true_false", "fill_blank"] = Field(..., description="题目类型")
    answer: str = Field(..., min_length=1, max_length=200, description="正确答案")
    options: list[str] | None = Field(None, description="选择题选项列表")
    question_level: str | None = Field(None, description="题目难度")

    @field_validator("options")
    @classmethod
    def choice_options_must_have_at_least_two(cls, v: str | None, info):
        if info.data.get("question_type") == "choice":
            if not v or len(v) < 2:
                raise ValueError("选择题至少需要 2 个选项")
            if len(v) != len(set(v)):
                raise ValueError("选项不能重复")
        return v

    @model_validator(mode="after")
    def choice_answer_must_be_in_options(self):
        if self.question_type == "choice" and self.options:
            if self.answer not in self.options:
                raise ValueError("答案必须在选项中")
        if self.question_type == "true_false":
            if self.answer.lower() not in ("true", "false"):
                raise ValueError("判断题答案只能为 true 或 false")
        return self


class QuestionUpdateRequest(BaseModel):
    """更新题目请求体（所有字段可选）。"""
    question: str | None = Field(None, min_length=1, max_length=500)
    answer: str | None = Field(None, min_length=1, max_length=200)
    options: list[str] | None = Field(None)
    question_level: str | None = Field(None)
    current_status: str | None = Field(None)

    @model_validator(mode="after")
    def at_least_one_field(self):
        if not any([self.question, self.answer, self.options is not None,
                    self.question_level, self.current_status]):
            raise ValueError("至少需要提供一个修改字段")
        return self


class StatusUpdateRequest(BaseModel):
    """状态更新请求体。"""
    status: Literal["active", "inactive"] = Field(..., description="目标状态")


class BatchDeleteRequest(BaseModel):
    """批量删除请求体。"""
    uuids: list[str] = Field(..., min_length=1, description="要删除的题目 UUID 列表")


class BatchStatusRequest(BaseModel):
    """批量状态更新请求体。"""
    uuids: list[str] = Field(..., min_length=1, description="要更新的题目 UUID 列表")
    status: Literal["active", "inactive"] = Field(..., description="目标状态")


@router.get("/questions/stats", response_model=dict[str, Any])
async def admin_questions_stats(
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：题目统计（按题型分布）。"""
    total = await RegisterQuestionsDAO.count_questions()
    choice_count = await RegisterQuestionsDAO.count_by_type("choice")
    true_false_count = await RegisterQuestionsDAO.count_by_type("true_false")
    fill_blank_count = await RegisterQuestionsDAO.count_by_type("fill_blank")
    return {
        "total": total,
        "choice": choice_count,
        "true_false": true_false_count,
        "fill_blank": fill_blank_count,
    }


@router.get("/questions", response_model=list[dict[str, Any]])
async def admin_list_questions(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    keyword: str | None = Query(None, description="搜索关键词（模糊匹配题目内容）"),
    question_type: str | None = Query(None, alias="type", description="按题型筛选"),
    status: str | None = Query(None, description="按状态筛选（active/inactive）"),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：分页搜索题目列表。"""
    return await RegisterQuestionsDAO.search_questions(
        keyword=keyword, question_type=question_type, status=status,
        limit=limit, offset=offset,
    )


@router.get("/questions/total", response_model=dict[str, Any])
async def admin_questions_total(
    keyword: str | None = Query(None),
    question_type: str | None = Query(None, alias="type"),
    status: str | None = Query(None),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：获取题目总数（可选筛选）。"""
    total = await RegisterQuestionsDAO.count_questions(
        keyword=keyword, question_type=question_type, status=status,
    )
    return {"total": total}


@router.post("/questions", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def admin_create_question(
    payload: QuestionCreateRequest,
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：创建题目。"""
    data = payload.model_dump(exclude_none=True)
    data["uuid"] = str(uuid_lib.uuid4())
    data["created_by"] = current_user["uuid"]
    data["current_status"] = "active"
    if data.get("options") is not None:
        data["options"] = json.dumps(data["options"], ensure_ascii=False)
    created = await RegisterQuestionsDAO.create(data)
    return created


@router.patch("/questions/{question_uuid}", response_model=dict[str, Any])
async def admin_update_question(
    question_uuid: str,
    payload: QuestionUpdateRequest,
    _current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：编辑题目。"""
    # 先查找题目，获取当前 question_type 以便校验
    existing = await RegisterQuestionsDAO().find_by_uuid(question_uuid)
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="题目不存在")

    data = payload.model_dump(exclude_none=True)
    if "options" in data:
        if data["options"] is not None:
            data["options"] = json.dumps(data["options"], ensure_ascii=False)
    if not data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="未提供要修改的字段")

    updated = await RegisterQuestionsDAO().update(question_uuid, data)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="题目不存在")
    return updated


@router.delete("/questions/{question_uuid}", response_model=dict[str, Any])
async def admin_delete_question(
    question_uuid: str,
    _current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：删除单题。"""
    ok = await RegisterQuestionsDAO().delete(question_uuid)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="题目不存在")
    return {"success": True}


@router.post("/questions/batch-delete", response_model=dict[str, Any])
async def admin_batch_delete_questions(
    payload: BatchDeleteRequest,
    _current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：批量删除题目。"""
    deleted = await RegisterQuestionsDAO.batch_delete_by_uuids(payload.uuids)
    return {"deleted": deleted}


@router.patch("/questions/batch-status", response_model=dict[str, Any])
async def admin_batch_update_question_status(
    payload: BatchStatusRequest,
    _current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：批量切换题目状态。"""
    updated = await RegisterQuestionsDAO.batch_update_status(payload.uuids, payload.status)
    return {"updated": updated}


@router.patch("/questions/{question_uuid}/status", response_model=dict[str, Any])
async def admin_update_question_status(
    question_uuid: str,
    payload: StatusUpdateRequest,
    _current_user: dict = Depends(get_current_user),
    _: dict = Depends(MinRoleChecker(Role.SUPERADMIN.value)),
):
    """管理员：单题切换状态。"""
    updated = await RegisterQuestionsDAO().update(question_uuid, {"current_status": payload.status})
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="题目不存在")
    return updated
```

- [ ] **Step 4: 运行测试验证通过**

```bash
cd /Users/huangtianrui/Documents/Project/jsshmzx/Tinder && python -m pytest tests/unit/test_api_v1_admin_questions.py --tb=short -v
```
Expected: ALL PASS (approximately 16 tests)

- [ ] **Step 5: 提交**

```bash
git -C /Users/huangtianrui/Documents/Project/jsshmzx/Tinder add tests/unit/test_api_v1_admin_questions.py modules/api/v1/admin.py
git -C /Users/huangtianrui/Documents/Project/jsshmzx/Tinder commit -m "feat(api): add register questions management endpoints"
```

---

### Task 3: 前端 API service + 类型定义

**Files:**
- Modify: `NavisBridge/src/typings/tinder.d.ts` — 新增 RegisterQuestion 类型
- Modify: `NavisBridge/src/services/admin.ts` — 新增注册问题 API 调用

**Interfaces:**
- Consumes: 后端 API 的请求/响应结构
- Produces: 前端可以直接调用的 `registerQuestionsService`

- [ ] **Step 1: 新增类型定义**

在 `NavisBridge/src/typings/tinder.d.ts` 中 `TotalResponse` 接口之后追加：

```typescript
  /** 注册问题列表项 */
  interface RegisterQuestion {
    id: number;
    uuid: string;
    question: string;
    question_type: 'choice' | 'true_false' | 'fill_blank';
    answer: string;
    options: string[] | null;
    question_level: string | null;
    current_status: string | null;
    created_by: string | null;
    created_at: string | null;
  }

  /** 注册问题统计 */
  interface QuestionStats {
    total: number;
    choice: number;
    true_false: number;
    fill_blank: number;
  }
```

- [ ] **Step 2: 新增 API service**

在 `NavisBridge/src/services/admin.ts` 末尾追加：

```typescript
// ─── 注册问题管理 ───────────────────────────────────────────────────────

/** 搜索题目列表 */
export async function searchQuestions(params: {
  limit?: number;
  offset?: number;
  keyword?: string;
  type?: string;
  status?: string;
}): Promise<API.RegisterQuestion[]> {
  const query = new URLSearchParams();
  if (params.limit !== undefined) query.set('limit', String(params.limit));
  if (params.offset !== undefined) query.set('offset', String(params.offset));
  if (params.keyword) query.set('keyword', params.keyword);
  if (params.type) query.set('type', params.type);
  if (params.status) query.set('status', params.status);
  const res = await fetch(
    `${getApiUrl()}/api/v1/admin/questions?${query.toString()}`,
    { headers: authHeaders() },
  );
  if (!res.ok) throw new Error('获取题目列表失败');
  return res.json();
}

/** 获取题目总数 */
export async function getQuestionsTotal(params?: {
  keyword?: string;
  type?: string;
  status?: string;
}): Promise<API.TotalResponse> {
  const query = new URLSearchParams();
  if (params?.keyword) query.set('keyword', params.keyword);
  if (params?.type) query.set('type', params.type);
  if (params?.status) query.set('status', params.status);
  const res = await fetch(
    `${getApiUrl()}/api/v1/admin/questions/total?${query.toString()}`,
    { headers: authHeaders() },
  );
  if (!res.ok) throw new Error('获取题目总数失败');
  return res.json();
}

/** 获取题目统计 */
export async function getQuestionStats(): Promise<API.QuestionStats> {
  const res = await fetch(`${getApiUrl()}/api/v1/admin/questions/stats`, {
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error('获取题目统计失败');
  return res.json();
}

/** 创建题目 */
export async function createQuestion(
  data: Record<string, unknown>,
): Promise<API.RegisterQuestion> {
  const res = await fetch(`${getApiUrl()}/api/v1/admin/questions`, {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || '创建题目失败');
  }
  return res.json();
}

/** 编辑题目 */
export async function updateQuestion(
  questionUuid: string,
  data: Record<string, unknown>,
): Promise<API.RegisterQuestion> {
  const res = await fetch(
    `${getApiUrl()}/api/v1/admin/questions/${questionUuid}`,
    {
      method: 'PATCH',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    },
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || '更新题目失败');
  }
  return res.json();
}

/** 删除单题 */
export async function deleteQuestion(questionUuid: string): Promise<void> {
  const res = await fetch(
    `${getApiUrl()}/api/v1/admin/questions/${questionUuid}`,
    { method: 'DELETE', headers: authHeaders() },
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || '删除题目失败');
  }
}

/** 批量删除题目 */
export async function batchDeleteQuestions(
  uuids: string[],
): Promise<{ deleted: number }> {
  const res = await fetch(
    `${getApiUrl()}/api/v1/admin/questions/batch-delete`,
    {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ uuids }),
    },
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || '批量删除失败');
  }
  return res.json();
}

/** 批量切换题目状态 */
export async function batchUpdateQuestionStatus(
  uuids: string[],
  status: string,
): Promise<{ updated: number }> {
  const res = await fetch(
    `${getApiUrl()}/api/v1/admin/questions/batch-status`,
    {
      method: 'PATCH',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ uuids, status }),
    },
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || '批量状态更新失败');
  }
  return res.json();
}

/** 单题切换状态 */
export async function updateQuestionStatus(
  questionUuid: string,
  status: string,
): Promise<API.RegisterQuestion> {
  const res = await fetch(
    `${getApiUrl()}/api/v1/admin/questions/${questionUuid}/status`,
    {
      method: 'PATCH',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    },
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || '状态更新失败');
  }
  return res.json();
}
```

- [ ] **Step 3: 提交**

```bash
git -C /Users/huangtianrui/Documents/Project/jsshmzx/NavisBridge add src/typings/tinder.d.ts src/services/admin.ts
git -C /Users/huangtianrui/Documents/Project/jsshmzx/NavisBridge commit -m "feat(admin): add register questions API service and types"
```

---

### Task 4: 前端注册问题管理页面

**Files:**
- Create: `NavisBridge/src/pages/RegisterQuestions/index.tsx` — 主页面

- [ ] **Step 1: 创建页面文件**

创建 `NavisBridge/src/pages/RegisterQuestions/index.tsx`，包含以下组件逻辑：

引用 `@/services/admin` 中的注册问题函数，`@/typings/tinder.d.ts` 中的类型。页面结构：

```tsx
import {
  batchDeleteQuestions,
  batchUpdateQuestionStatus,
  createQuestion,
  deleteQuestion,
  getQuestionStats,
  getQuestionsTotal,
  searchQuestions,
  updateQuestion,
  updateQuestionStatus,
} from '@/services/admin';
import {
  ActionType,
  FooterToolbar,
  PageContainer,
  ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import {
  Badge,
  Button,
  Card,
  Col,
  Collapse,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  message,
  Modal,
  Radio,
  Row,
  Select,
  Space,
  Statistic,
  Tag,
} from 'antd';
import React, { useEffect, useRef, useState } from 'react';

const QUESTION_TYPE_LABELS: Record<string, string> = {
  choice: '选择题',
  true_false: '判断题',
  fill_blank: '填空题',
};

const QUESTION_TYPE_COLORS: Record<string, string> = {
  choice: 'blue',
  true_false: 'purple',
  fill_blank: 'cyan',
};

const STATUS_COLORS: Record<string, string> = {
  active: 'green',
  inactive: 'default',
};

const STATUS_LABELS: Record<string, string> = {
  active: '启用',
  inactive: '禁用',
};

const LEVEL_LABELS: Record<string, string> = {
  easy: '简单',
  medium: '中等',
  hard: '困难',
};

const RegisterQuestions: React.FC = () => {
  const actionRef = useRef<ActionType>();
  const [stats, setStats] = useState<API.QuestionStats | null>(null);
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  const [selectedRows, setSelectedRows] = useState<API.RegisterQuestion[]>([]);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selectedQuestion, setSelectedQuestion] = useState<API.RegisterQuestion | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingQuestion, setEditingQuestion] = useState<API.RegisterQuestion | null>(null);
  const [form] = Form.useForm();
  const [deleteModalVisible, setDeleteModalVisible] = useState(false);
  const [pendingDeleteUuid, setPendingDeleteUuid] = useState<string | null>(null);
  const [batchStatusModalVisible, setBatchStatusModalVisible] = useState(false);
  const [batchStatusForm] = Form.useForm();

  // 加载统计
  useEffect(() => {
    getQuestionStats().then(setStats).catch(() => {});
  }, []);

  // Typed columns
  const columns: ProColumns<API.RegisterQuestion>[] = [
    {
      title: 'ID',
      dataIndex: 'id',
      width: 60,
      search: false,
    },
    {
      title: '题目',
      dataIndex: 'question',
      width: 300,
      ellipsis: true,
    },
    {
      title: '类型',
      dataIndex: 'question_type',
      width: 80,
      valueType: 'select',
      valueEnum: {
        choice: { text: '选择题', status: 'Processing' },
        true_false: { text: '判断题', status: 'Processing' },
        fill_blank: { text: '填空题', status: 'Processing' },
      },
      render: (_, record) => (
        <Tag color={QUESTION_TYPE_COLORS[record.question_type]}>
          {QUESTION_TYPE_LABELS[record.question_type] || record.question_type}
        </Tag>
      ),
    },
    {
      title: '难度',
      dataIndex: 'question_level',
      width: 80,
      search: false,
      render: (_, record) =>
        record.question_level ? (
          <Tag>{LEVEL_LABELS[record.question_level] || record.question_level}</Tag>
        ) : (
          '-'
        ),
    },
    {
      title: '状态',
      dataIndex: 'current_status',
      width: 80,
      valueType: 'select',
      valueEnum: {
        active: { text: '启用', status: 'Success' },
        inactive: { text: '禁用', status: 'Default' },
      },
      render: (_, record) => (
        <Badge
          status={
            (STATUS_COLORS[record.current_status || ''] || 'default') as
              | 'success'
              | 'default'
          }
          text={STATUS_LABELS[record.current_status || ''] || record.current_status || '未知'}
        />
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 160,
      valueType: 'dateTime',
      search: false,
    },
    {
      title: '操作',
      width: 160,
      key: 'option',
      valueType: 'option',
      render: (_, record) => [
        <a
          key="detail"
          onClick={() => {
            setSelectedQuestion(record);
            setDrawerOpen(true);
          }}
        >
          详情
        </a>,
        <a
          key="edit"
          onClick={() => {
            setEditingQuestion(record);
            form.setFieldsValue({
              question: record.question,
              question_type: record.question_type,
              question_level: record.question_level,
              answer: record.answer,
              options: record.options || [],
            });
            setModalOpen(true);
          }}
        >
          编辑
        </a>,
        <a
          key="delete"
          style={{ color: 'red' }}
          onClick={() => {
            setPendingDeleteUuid(record.uuid);
            setDeleteModalVisible(true);
          }}
        >
          删除
        </a>,
      ],
    },
  ];

  const showCreate = () => {
    setEditingQuestion(null);
    form.resetFields();
    form.setFieldsValue({ question_type: 'choice', options: ['', ''] });
    setModalOpen(true);
  };

  const refreshStats = () => {
    getQuestionStats().then(setStats).catch(() => {});
  };

  // Handle form submit for create/edit
  const handleFormSubmit = async () => {
    try {
      const values = await form.validateFields();
      const payload: Record<string, unknown> = {
        question: values.question,
        question_type: values.question_type,
        answer: values.answer,
      };
      if (values.question_level) payload.question_level = values.question_level;
      if (values.question_type === 'choice' && values.options) {
        payload.options = values.options.filter((o: string) => o.trim() !== '');
      }
      if (editingQuestion) {
        await updateQuestion(editingQuestion.uuid, payload);
        message.success('更新成功');
      } else {
        await createQuestion(payload);
        message.success('创建成功');
      }
      setModalOpen(false);
      actionRef.current?.reload();
      refreshStats();
    } catch (err: any) {
      if (err?.errorFields) return;
      message.error(err?.message || '操作失败');
    }
  };

  // Single delete
  const handleDeleteConfirm = async () => {
    if (!pendingDeleteUuid) return;
    try {
      await deleteQuestion(pendingDeleteUuid);
      message.success('删除成功');
      actionRef.current?.reload();
      refreshStats();
      setDrawerOpen(false);
    } catch (err: any) {
      message.error(err?.message || '删除失败');
    } finally {
      setDeleteModalVisible(false);
      setPendingDeleteUuid(null);
    }
  };

  // Batch delete
  const handleBatchDelete = () => {
    Modal.confirm({
      title: '批量删除',
      content: `确定要删除选中的 ${selectedRowKeys.length} 个题目吗？`,
      okText: '确定',
      cancelText: '取消',
      okType: 'danger',
      onOk: async () => {
        try {
          const result = await batchDeleteQuestions(
            selectedRows.map((r) => r.uuid),
          );
          message.success(`已成功删除 ${result.deleted} 个题目`);
          setSelectedRowKeys([]);
          setSelectedRows([]);
          actionRef.current?.reload();
          refreshStats();
        } catch (err: any) {
          message.error(err?.message || '批量删除失败');
        }
      },
    });
  };

  // Batch status update
  const handleBatchStatus = async () => {
    try {
      const values = await batchStatusForm.validateFields();
      const result = await batchUpdateQuestionStatus(
        selectedRows.map((r) => r.uuid),
        values.status,
      );
      message.success(`已成功更新 ${result.updated} 个题目的状态`);
      setBatchStatusModalVisible(false);
      setSelectedRowKeys([]);
      setSelectedRows([]);
      batchStatusForm.resetFields();
      actionRef.current?.reload();
      refreshStats();
    } catch (err: any) {
      if (err?.errorFields) return;
      message.error(err?.message || '批量状态更新失败');
    }
  };

  // Toggle single status
  const handleToggleStatus = async (record: API.RegisterQuestion) => {
    const newStatus = record.current_status === 'active' ? 'inactive' : 'active';
    try {
      await updateQuestionStatus(record.uuid, newStatus);
      message.success(newStatus === 'active' ? '已启用' : '已禁用');
      actionRef.current?.reload();
      setDrawerOpen(false);
    } catch (err: any) {
      message.error(err?.message || '状态更新失败');
    }
  };

  // Watch question_type to show/hide options field
  const questionType = Form.useWatch('question_type', form);

  return (
    <PageContainer header={{ title: '注册问题管理' }}>
      {/* 统计卡片 */}
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={6}>
          <Card size="small">
            <Statistic title="总题目" value={stats?.total || 0} />
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <Statistic title="选择题" value={stats?.choice || 0} valueStyle={{ color: '#1677ff' }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <Statistic title="判断题" value={stats?.true_false || 0} valueStyle={{ color: '#722ed1' }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <Statistic title="填空题" value={stats?.fill_blank || 0} valueStyle={{ color: '#13c2c2' }} />
          </Card>
        </Col>
      </Row>

      {/* 题目列表 */}
      <ProTable<API.RegisterQuestion>
        actionRef={actionRef}
        rowKey="uuid"
        columns={columns}
        request={async (params) => {
          const { current, pageSize, ...rest } = params as any;
          const keyword = (rest.keyword as string) || undefined;
          const type = (rest.question_type as string) || undefined;
          const status = (rest.current_status as string) || undefined;
          const [data, totalRes] = await Promise.all([
            searchQuestions({
              limit: pageSize || 20,
              offset: ((current || 1) - 1) * (pageSize || 20),
              keyword,
              type,
              status,
            }),
            getQuestionsTotal({ keyword, type, status }),
          ]);
          return { data, success: true, total: totalRes.total };
        }}
        toolBarRender={() => [
          <Button key="create" type="primary" onClick={showCreate}>
            新建题目
          </Button>,
        ]}
        search={{
          labelWidth: 'auto',
          defaultCollapsed: false,
          optionRender: (searchConfig, props, dom) => [...dom.reverse()],
        }}
        pagination={{
          defaultPageSize: 20,
          showSizeChanger: true,
          pageSizeOptions: [20, 50, 100, 200, 500],
        }}
        rowSelection={{
          selectedRowKeys,
          onChange: (keys, rows) => {
            setSelectedRowKeys(keys);
            setSelectedRows(rows);
          },
        }}
      />

      {/* 批量操作栏 */}
      {selectedRowKeys.length > 0 && (
        <FooterToolbar
          extra={
            <div>
              已选择 <a style={{ fontWeight: 600 }}>{selectedRowKeys.length}</a> 个题目
            </div>
          }
        >
          <Button onClick={() => setBatchStatusModalVisible(true)}>批量切换状态</Button>
          <Button danger onClick={handleBatchDelete}>
            批量删除
          </Button>
        </FooterToolbar>
      )}

      {/* 详情抽屉 */}
      <Drawer
        width={560}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title="题目详情"
      >
        {selectedQuestion && (
          <>
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="UUID">{selectedQuestion.uuid}</Descriptions.Item>
              <Descriptions.Item label="题目">{selectedQuestion.question}</Descriptions.Item>
              <Descriptions.Item label="类型">
                <Tag color={QUESTION_TYPE_COLORS[selectedQuestion.question_type]}>
                  {QUESTION_TYPE_LABELS[selectedQuestion.question_type]}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="难度">
                {selectedQuestion.question_level
                  ? LEVEL_LABELS[selectedQuestion.question_level] || selectedQuestion.question_level
                  : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="正确答案">{selectedQuestion.answer}</Descriptions.Item>
              <Descriptions.Item label="选项">
                {selectedQuestion.options && selectedQuestion.options.length > 0
                  ? selectedQuestion.options.join(' / ')
                  : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <Badge
                  status={
                    (STATUS_COLORS[selectedQuestion.current_status || ''] || 'default') as any
                  }
                  text={
                    STATUS_LABELS[selectedQuestion.current_status || ''] ||
                    selectedQuestion.current_status ||
                    '未知'
                  }
                />
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">{selectedQuestion.created_at || '-'}</Descriptions.Item>
              <Descriptions.Item label="创建者">{selectedQuestion.created_by || '-'}</Descriptions.Item>
            </Descriptions>
            <Space style={{ marginTop: 16 }}>
              <Button
                type={selectedQuestion.current_status === 'active' ? 'default' : 'primary'}
                onClick={() => handleToggleStatus(selectedQuestion)}
              >
                {selectedQuestion.current_status === 'active' ? '禁用' : '启用'}
              </Button>
            </Space>
          </>
        )}
      </Drawer>

      {/* 新建/编辑弹窗 */}
      <Modal
        title={editingQuestion ? '编辑题目' : '新建题目'}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={handleFormSubmit}
        width={600}
        destroyOnClose
      >
        <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item
            label="题目内容"
            name="question"
            rules={[{ required: true, message: '请输入题目内容' }]}
          >
            <Input.TextArea rows={3} />
          </Form.Item>
          <Form.Item
            label="题目类型"
            name="question_type"
            rules={[{ required: true, message: '请选择题目类型' }]}
          >
            <Select
              options={[
                { label: '选择题', value: 'choice' },
                { label: '判断题', value: 'true_false' },
                { label: '填空题', value: 'fill_blank' },
              ]}
            />
          </Form.Item>
          <Form.Item label="难度" name="question_level">
            <Select
              allowClear
              placeholder="请选择难度"
              options={[
                { label: '简单', value: 'easy' },
                { label: '中等', value: 'medium' },
                { label: '困难', value: 'hard' },
              ]}
            />
          </Form.Item>

          {/* 选择题选项区域 */}
          {questionType === 'choice' && (
            <Form.List name="options">
              {(fields, { add, remove }) => (
                <>
                  {fields.map(({ key, name, ...restField }, index) => (
                    <Row key={key} gutter={8} align="middle" style={{ marginBottom: 8 }}>
                      <Col>
                        <Tag>{String.fromCharCode(65 + index)}</Tag>
                      </Col>
                      <Col flex="auto">
                        <Form.Item
                          {...restField}
                          name={name}
                          rules={[{ required: true, message: '请输入选项内容' }]}
                          noStyle
                        >
                          <Input placeholder={`选项 ${String.fromCharCode(65 + index)}`} />
                        </Form.Item>
                      </Col>
                      <Col>
                        {fields.length > 2 && (
                          <Button type="link" danger onClick={() => remove(name)}>
                            删除
                          </Button>
                        )}
                      </Col>
                    </Row>
                  ))}
                  <Form.Item>
                    <Button type="dashed" onClick={() => add('', fields.length)} block>
                      + 添加选项
                    </Button>
                  </Form.Item>
                </>
              )}
            </Form.List>
          )}

          {/* 正确答案 */}
          <Form.Item
            label="正确答案"
            name="answer"
            rules={[{ required: true, message: '请输入正确答案' }]}
          >
            {questionType === 'choice' ? (
              // For choice, the answer is selected from options
              <Form.Item noStyle name="answer" rules={[{ required: true, message: '请选择正确答案' }]}>
                <Select placeholder="请选择正确答案">
                  {(() => {
                    const opts = form.getFieldValue('options') || [];
                    return opts
                      .filter((o: string) => o.trim() !== '')
                      .map((o: string, i: number) => (
                        <Select.Option key={o} value={o}>
                          {String.fromCharCode(65 + i)}. {o}
                        </Select.Option>
                      ));
                  })()}
                </Select>
              </Form.Item>
            ) : questionType === 'true_false' ? (
              <Radio.Group>
                <Radio value="true">正确</Radio>
                <Radio value="false">错误</Radio>
              </Radio.Group>
            ) : (
              <Input placeholder="请输入正确答案" />
            )}
          </Form.Item>
        </Form>
      </Modal>

      {/* 批量状态切换弹窗 */}
      <Modal
        title={`批量切换状态（已选 ${selectedRowKeys.length} 个题目）`}
        open={batchStatusModalVisible}
        onCancel={() => {
          setBatchStatusModalVisible(false);
          batchStatusForm.resetFields();
        }}
        onOk={handleBatchStatus}
        width={400}
        destroyOnClose
      >
        <Form
          form={batchStatusForm}
          layout="vertical"
          style={{ marginTop: 16 }}
        >
          <Form.Item
            label="目标状态"
            name="status"
            rules={[{ required: true, message: '请选择目标状态' }]}
          >
            <Select
              options={[
                { label: '启用', value: 'active' },
                { label: '禁用', value: 'inactive' },
              ]}
            />
          </Form.Item>
        </Form>
      </Modal>

      {/* 删除确认弹窗 */}
      <Modal
        title="确认删除"
        open={deleteModalVisible}
        onCancel={() => {
          setDeleteModalVisible(false);
          setPendingDeleteUuid(null);
        }}
        onOk={handleDeleteConfirm}
        okText="确认删除"
        okType="danger"
        cancelText="取消"
        width={400}
      >
        <p>确定要删除这个题目吗？此操作不可恢复。</p>
      </Modal>
    </PageContainer>
  );
};

export default RegisterQuestions;
```

> 注意：上述代码中 `Form.useWatch` 在 Ant Design 5 中用于监听 `question_type` 字段变化，动态切换选项和正确答案的 UI。

- [ ] **Step 2: 注册路由**

修改 `NavisBridge/.umirc.ts`，在 `routes` 数组中追加：

```typescript
    {
      name: '注册问题管理',
      path: '/register-questions',
      component: './RegisterQuestions',
    },
```

放在用户管理路由之后。

- [ ] **Step 3: 提交**

```bash
git -C /Users/huangtianrui/Documents/Project/jsshmzx/NavisBridge add src/pages/RegisterQuestions/index.tsx .umirc.ts
git -C /Users/huangtianrui/Documents/Project/jsshmzx/NavisBridge commit -m "feat: add register questions management page"
```

---

### Task 5: 验证

- [ ] **Step 1: 运行后端单元测试**

```bash
cd /Users/huangtianrui/Documents/Project/jsshmzx/Tinder && python -m pytest tests/unit/ --tb=short -v
```
Expected: ALL PASS (auth tests + admin questions tests)

- [ ] **Step 2: 运行数据库迁移**

```bash
cd /Users/huangtianrui/Documents/Project/jsshmzx/Tinder && python db_migrate.py
```
Expected: SQL executed successfully.

- [ ] **Step 3: 启动前端验证构建**

```bash
cd /Users/huangtianrui/Documents/Project/jsshmzx/NavisBridge && pnpm build
```
Expected: Build succeeds without errors.
