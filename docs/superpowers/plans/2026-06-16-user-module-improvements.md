# 用户模块改进 — 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将用户模块从 bcrypt/OAuth2 表单迁移到 SHA256 双重哈希 + JSON 登录，完善两步注册流程，新增账号注销（30 天冷却期）和定时清理模块。

**Architecture:** 新建 `core/security/password.py` 作为纯 SHA256 直通模块，`core/security/hash.py` 桥接到它（保持现有 `get_password_hash`/`verify_password` 签名不变）。注册改为三步：获取答题卡 → 答题拿临时 token → 设密码+用户名。定时清理使用 apscheduler AsyncIOScheduler，独立于 `core/cron/` 模块。

**Tech Stack:** FastAPI + SQLAlchemy async + Redis + python-jose (JWT) + apscheduler

**Spec:** `docs/superpowers/specs/2026-06-16-user-module-improvements-design.md`

**Attention:** 不修改测试文件、文档、admin 模块。项目当前无用户，无需旧格式兼容。

---

## 文件结构

| 文件 | 操作 | 职责 |
|------|------|------|
| `core/security/password.py` | **新建** | SHA256 双重哈希直通（`hash_password` / `verify_password`） |
| `core/security/hash.py` | **修改** | 桥接到 `password.py`，保持现有函数签名 |
| `core/security/jwt_handler.py` | **修改** | 新增 `create_temp_token`（含 purpose 声明） |
| `core/database/migrations/SQL/alter_users_add_deletion_scheduled_at.sql` | **新建** | 新增 `deletion_scheduled_at` 列 |
| `core/database/migrations/migration_history.py` | **修改** | 追加迁移文件名 |
| `core/database/dao/users.py` | **修改** | ORM 新增 `deletion_scheduled_at` 列；新增 `find_by_username` |
| `core/middleware/auth/dependencies.py` | **修改** | 新增 `get_temp_user` 依赖（验证 `purpose="register_complete"`） |
| `modules/api/v1/auth.py` | **修改** | 登录改 JSON body + `pending_deletion` 恢复逻辑；移除 `/me` |
| `modules/api/v1/users.py` | **修改** | 注册改为临时 token；新增 `/register/sheet/request`、`/register/complete`、`GET /me`、`DELETE /me`；密码修改适配 SHA256 |
| `core/cron/__init__.py` | **新建** | 定时任务模块入口 |
| `core/cron/scheduler.py` | **新建** | AsyncIOScheduler 启停 |
| `core/cron/tasks/__init__.py` | **新建** | 任务包入口 |
| `core/cron/tasks/cleanup_users.py` | **新建** | 每小时清理过期注销账号 |
| `server.py` | **修改** | lifespan 中启停调度器 |
| `requirements.txt` | **修改** | 新增 `apscheduler` |

**不需要修改：**
- `modules/api/v1/router.py` — 所有新端点挂在已有 auth/users router 下，无需改聚合层
- `modules/api/v1/admin.py` — admin 模块通过 `hash.py` 桥接自动获得新行为
- `core/database/dao/refresh_tokens.py` — revoke_all_for_user 已存在，无需改动

---

### Task 1: 密码模块 — `core/security/password.py`

**Files:**
- Create: `core/security/password.py`

- [ ] **Step 1: 创建 password.py**

```python
"""SHA256 双重哈希密码模块。

客户端在发送前自行计算 SHA256(SHA256(明文)) → 64 字符 hex 字符串，
服务端直接存储和比对，不做额外哈希。
"""

import hmac


def hash_password(password: str) -> str:
    """接收客户端传来的 SHA256 hex 字符串，直接返回（服务端不额外哈希）。

    Args:
        password: 64 字符 hex 字符串（SHA256 双重哈希结果）

    Returns:
        原样返回，用于直接存入数据库
    """
    return password


def verify_password(password: str, stored_hash: str) -> bool:
    """常量时间比对密码 hex 字符串（防止 timing attack）。

    Args:
        password: 客户端传来的 SHA256 hex 字符串
        stored_hash: 数据库中存储的 SHA256 hex 字符串

    Returns:
        bool: 是否匹配
    """
    return hmac.compare_digest(password, stored_hash)
```

- [ ] **Step 2: 验证模块可导入**

```bash
python -c "from core.security.password import hash_password, verify_password; print('OK')"
```

---

### Task 2: Hash 桥接 — `core/security/hash.py`

**Files:**
- Modify: `core/security/hash.py`

- [ ] **Step 1: 替换 bcrypt 为 password.py 桥接**

将 `core/security/hash.py` 当前内容（使用 passlib CryptContext 的 bcrypt）替换为：

```python
"""密码哈希模块 — 桥接到 core.security.password。

现有调用方（auth、users、admin）的 import 路径不变，
内部逻辑已切换为 SHA256 双重哈希直通。
"""

from core.security.password import hash_password as _hash
from core.security.password import verify_password as _verify


def get_password_hash(password: str) -> str:
    """对密码进行哈希处理（SHA256 双重哈希，服务端直接存储）。

    Args:
        password: 64 字符 hex 字符串（客户端已做 SHA256 双重哈希）

    Returns:
        原样返回 hex 字符串
    """
    return _hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证明文 SHA256 hex 字符串与存储值是否匹配（常量时间比对）。

    Args:
        plain_password: 客户端传来的 SHA256 hex 字符串
        hashed_password: 数据库中存储的 SHA256 hex 字符串

    Returns:
        bool: 是否匹配
    """
    return _verify(plain_password, hashed_password)
```

- [ ] **Step 2: 验证 hash.py 可正常导入且函数签名不变**

```bash
python -c "from core.security.hash import get_password_hash, verify_password; h=get_password_hash('a'*64); print('OK' if verify_password('a'*64, h) else 'FAIL')"
```

---

### Task 3: JWT 临时 token — `core/security/jwt_handler.py`

**Files:**
- Modify: `core/security/jwt_handler.py`

- [ ] **Step 1: 新增 `create_temp_token` 函数**

在 `generate_refresh_token` 函数之后（文件末尾）添加：

```python
def create_temp_token(subject: str, purpose: str, expires_minutes: int = 15) -> str:
    """创建临时 JWT token，仅用于特定目的（如注册完成）。

    与 create_access_token 的区别：
    - payload 含 purpose 声明，get_temp_user 依赖据此放行
    - 默认 15 分钟过期

    Args:
        subject: 用户 uuid
        purpose: token 用途标识（如 "register_complete"）
        expires_minutes: 过期时间（分钟），默认 15

    Returns:
        JWT 字符串
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode = {"exp": expire, "sub": str(subject), "purpose": purpose}
    encoded_jwt = jwt.encode(to_encode, _get_jwt_secret(), algorithm=ALGORITHM)
    return encoded_jwt
```

- [ ] **Step 2: 验证临时 token 生成和解码**

```bash
python -c "
from core.security.jwt_handler import create_temp_token, decode_access_token
t = create_temp_token('test-uuid', 'register_complete', 15)
p = decode_access_token(t)
assert p['sub'] == 'test-uuid'
assert p['purpose'] == 'register_complete'
print('OK')
"
```

---

### Task 4: 数据库迁移 + ORM + 历史

**Files:**
- Create: `core/database/migrations/SQL/alter_users_add_deletion_scheduled_at.sql`
- Modify: `core/database/dao/users.py`
- Modify: `core/database/migrations/migration_history.py`

- [ ] **Step 1: 创建迁移 SQL 文件**

写入 `core/database/migrations/SQL/alter_users_add_deletion_scheduled_at.sql`：

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS deletion_scheduled_at TIMESTAMP NULL;
```

- [ ] **Step 2: User ORM 模型新增列**

在 `core/database/dao/users.py` 的 `User` 类中，在 `password` 列之后添加新列：

```python
deletion_scheduled_at: Mapped[datetime | None] = mapped_column(TIMESTAMP)
```

精确编辑位置：在 `password: Mapped[str | None] = mapped_column(Text)` 行之后插入一行。

- [ ] **Step 3: UsersDAO 新增 `find_by_username` 静态方法**

在 `core/database/dao/users.py` 的 `UsersDAO` 类中，`find_password_hash` 方法之后添加：

```python
@staticmethod
async def find_by_username(session: AsyncSession, username: str) -> User | None:
    """根据 username 精确查找用户，不存在返回 None。"""
    result = await session.scalars(
        select(User).where(User.username == username)
    )
    return result.first()
```

- [ ] **Step 4: 追加迁移历史**

在 `core/database/migrations/migration_history.py` 的 `migration_history` 列表末尾追加：

```python
"alter_users_add_deletion_scheduled_at.sql",
```

- [ ] **Step 5: 运行迁移验证**

```bash
python db_migrate.py
```

---

### Task 5: 认证依赖 — `core/middleware/auth/dependencies.py`

**Files:**
- Modify: `core/middleware/auth/dependencies.py`

- [ ] **Step 1: 新增 `get_temp_user` 依赖**

在文件末尾新增 `get_temp_user` 函数。先在文件顶部添加 `HTTPBearer` 导入，修改 `from fastapi.security import OAuth2PasswordBearer` 为：

```python
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
```

然后在模块级别创建 `temp_token_scheme` 实例（放在 `oauth2_scheme` 下方）：

```python
temp_token_scheme = HTTPBearer()
```

在文件末尾（`MinRoleChecker` 类之后）添加：

```python
async def get_temp_user(
    credentials: HTTPAuthorizationCredentials = Depends(temp_token_scheme),
) -> dict:
    """验证临时 token（purpose="register_complete"），返回用户字典。

    与 get_current_user 区别：
    - 不检查用户角色
    - 要求 payload.purpose == "register_complete"
    - 不读取 Redis 缓存（临时 token 一次性使用）
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无效或已过期的临时凭证",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise credentials_exception

    purpose = payload.get("purpose")
    if purpose != "register_complete":
        raise credentials_exception

    user_uuid: str | None = payload.get("sub")
    if user_uuid is None:
        raise credentials_exception

    user_dict = await UsersDAO().find_by_uuid(user_uuid)
    if user_dict is None:
        raise credentials_exception

    user_dict.pop("password", None)
    return user_dict
```

- [ ] **Step 2: 验证导入**

```bash
python -c "from core.middleware.auth.dependencies import get_temp_user; print('OK')"
```

---

### Task 6: Auth 模块 — `modules/api/v1/auth.py`

**Files:**
- Modify: `modules/api/v1/auth.py`

- [ ] **Step 1: 将 OAuth2PasswordRequestForm 替换为 JSON LoginRequest**

修改导入部分：移除 `from fastapi.security import OAuth2PasswordRequestForm`，在 `RefreshRequest` 类之前添加：

```python
class LoginRequest(BaseModel):
    """JSON 登录请求体。"""

    username: str = Field(..., min_length=1, description="用户名或邮箱")
    password: str = Field(..., min_length=1, description="SHA256 双重哈希后的 hex 字符串（64 字符）")
```

注意：`Field` 需要导入，将 `from pydantic import BaseModel` 改为：

```python
from pydantic import BaseModel, Field
```

- [ ] **Step 2: 重写 `/login` 端点 — JSON body + pending_deletion 恢复**

将现有的 `@router.post("/login", ...)` 函数替换为：

```python
@router.post("/login", response_model=dict[str, Any])
async def login(request: Request, body: LoginRequest):
    """用户登录，返回 Access Token 和 Refresh Token。

    支持 username 或 email 作为登录标识。
    密码为客户端 SHA256 双重哈希后的 64 字符 hex 字符串。
    若账号处于 pending_deletion 冷却期中，自动恢复为 normal。
    """

    # 速率限制：IP 级别和用户名级别
    client_ip = request.client.host if request.client else "unknown"
    ip_key = f"login_atm:ip:{client_ip}:min"
    un_key = f"login_atm:un:{body.username}:min"

    ip_count = _login_redis_incr(ip_key, _LOGIN_RATE_WINDOW_SECONDS)
    un_count = _login_redis_incr(un_key, _LOGIN_RATE_WINDOW_SECONDS)

    if ip_count > _LOGIN_MAX_ATTEMPTS_PER_IP_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="登录尝试过于频繁，请稍后再试",
        )
    if un_count > _LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="登录尝试过于频繁，请稍后再试",
        )

    async with get_session() as session:
        user = await UsersDAO.find_by_username_or_email(session, body.username)
        if not user or not user.password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="用户名或密码错误",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not verify_password(body.password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="用户名或密码错误",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 检查账号状态
        user_uuid = str(user.uuid)
        status_val = user.current_status

        if status_val in ("disabled", "banned"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="账号已被禁用，如有疑问请联系管理员",
            )

        if status_val == "pending_deletion":
            deletion_time = user.deletion_scheduled_at
            now_utc = datetime.now(timezone.utc)
            if deletion_time and deletion_time > now_utc:
                # 冷却期内登录 → 自动恢复
                await UsersDAO().update(user_uuid, {
                    "current_status": "normal",
                    "deletion_scheduled_at": None,
                })
                custom_log("SUCCESS", f"[Login] uuid={user_uuid} 冷却期内登录，账号已恢复")
            else:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="账号已永久注销",
                )

    access_token = create_access_token(subject=user_uuid)
    plaintext, token_hash = generate_refresh_token()

    await RefreshTokensDAO.create(user_uuid=user_uuid, token_hash=token_hash)
    await UsersDAO().update(user_uuid, {
        "last_login_at": datetime.now(timezone.utc),
        "last_login_ip": client_ip,
    })

    return {
        "access_token": access_token,
        "refresh_token": plaintext,
        "token_type": "bearer",
    }
```

- [ ] **Step 3: 删除 `GET /me` 端点**

删除 `read_users_me` 函数及其装饰器（约行 101-108）。该端点已迁移到 `users.py`。

- [ ] **Step 4: 更新 refresh 端点 — 允许 `pending_deletion` 用户刷新 token**

将 `POST /refresh` 中的状态检查从：

```python
if user.get("current_status") not in (None, "normal"):
```

改为：

```python
if user.get("current_status") in ("disabled", "banned"):
```

这允许 `pending_deletion` 用户（冷却期内）也能刷新 token，保持登录状态。

- [ ] **Step 5: 清理不再使用的导入**

删除 `from core.middleware.auth.dependencies import get_current_user`（如果后续端点都不使用）。检查确认 `/refresh` 和 `/logout` 不使用 `get_current_user`（logout 仍使用，保留导入）。

检查最终导入列表应为：

```python
import hashlib
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from core.database.connection.pgsql import get_session
from core.database.dao.users import UsersDAO
from core.database.dao.refresh_tokens import RefreshTokensDAO
from core.security.hash import verify_password
from core.security.jwt_handler import create_access_token, generate_refresh_token
from core.middleware.auth.dependencies import get_current_user
```

（`get_current_user` 仍被 `/logout` 使用，保留。）

---

### Task 7: Users 模块 — 注册端点改造

**Files:**
- Modify: `modules/api/v1/users.py`

- [ ] **Step 1: 更新模块 docstring 并修改导入**

将 `users.py` 顶部 docstring 替换为新的三步注册流程描述：

```python
"""用户模块 — 注册、个人信息、注销。

注册流程（三步）
--------------
1. POST /users/register/sheet/request
   获取答题卡（IP 每日 4 次），返回 sheet_id + 5 道不含答案的题目。
   
2. POST /users/register
   提交答案（IP 每日 10 次 / 姓名每日 3 次 / 每答题卡 3 次），
   至少答对 3 道 → 创建用户（password=NULL）→ 颁发临时 token（15min）。
   
3. POST /users/register/complete
   携带临时 token，设置 username + password + email → 返回正式 JWT token。

其他端点
--------
- GET    /users/me              — 获取完整个人信息
- PATCH  /users/me/password     — 修改密码
- PATCH  /users/me/profile      — 修改个人信息
- DELETE /users/me              — 账号注销（30 天冷却期）
"""
```

修改导入行：
- `from datetime import date` → `from datetime import date, datetime, timedelta, timezone`
- 添加 `from core.middleware.auth.dependencies import get_current_user, get_temp_user, invalidate_user_cache`

最终导入块应为：

```python
import json
import uuid as uuid_lib
from datetime import date, datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator, model_validator

from core.database.connection.pgsql import get_session
from core.database.connection.redis import redis_conn
from core.database.dao.refresh_tokens import RefreshTokensDAO
from core.database.dao.register_questions import RegisterQuestionsDAO
from core.database.dao.users import UsersDAO
from core.helper.CustomLog.index import custom_log
from core.middleware.auth.dependencies import get_current_user, get_temp_user, invalidate_user_cache
from core.middleware.firewall.helpers import get_client_ip
from core.security.hash import get_password_hash, verify_password
from core.security.jwt_handler import create_access_token, create_temp_token, generate_refresh_token
```

- [ ] **Step 2: 将 `GET /register/questions` 改为 `POST /register/sheet/request`**

将：

```python
@router.get("/register/questions", response_model=dict[str, Any])
async def get_register_questions(request: Request):
```

改为：

```python
@router.post("/register/sheet/request", response_model=dict[str, Any])
async def request_register_sheet(request: Request):
```

函数内部逻辑保持不变（速率限制、随机抽题、Redis 存储、返回 sheet_id + questions）。

- [ ] **Step 3: 修改 `POST /register` — 返回临时 token 而非正式 token**

替换 `register_user` 函数末尾的 "步骤 7" 部分（约行 374-393）。将：

```python
    # ----------------------------------------------------------------
    # 步骤 7：生成初始 JWT token 并返回
    # ----------------------------------------------------------------
    access_token = create_access_token(subject=new_uuid)
    custom_log("SUCCESS", f"[Register] 新用户注册成功 uuid={new_uuid} real_name='{body.real_name}'")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "uuid": created_user["uuid"],
            "nickname": created_user["nickname"],
            "real_name": created_user["real_name"],
            "class": created_user.get("class"),
            "class_type": created_user["class_type"],
            "role": created_user["user_role"],
            "is_verified": created_user["is_verified"],
            "status": created_user["current_status"],
        },
    }
```

改为：

```python
    # ----------------------------------------------------------------
    # 步骤 7：颁发临时 token（仅用于 Step 2 完成注册）
    # ----------------------------------------------------------------
    temp_token = create_temp_token(subject=new_uuid, purpose="register_complete", expires_minutes=15)
    custom_log("SUCCESS", f"[Register] 新用户答题通过 uuid={new_uuid} real_name='{body.real_name}'")

    return {
        "temp_token": temp_token,
        "token_type": "bearer",
        "expires_in": 900,
        "user": {
            "uuid": created_user["uuid"],
            "nickname": created_user["nickname"],
            "real_name": created_user["real_name"],
            "class": created_user.get("class"),
            "class_type": created_user["class_type"],
            "role": created_user["user_role"],
            "is_verified": created_user["is_verified"],
            "status": created_user["current_status"],
        },
    }
```

- [ ] **Step 4: 新增 Pydantic 模型 — `CompleteRegisterRequest`**

在 `UpdateProfileRequest` 类之前（约行 421 附近）添加：

```python
class CompleteRegisterRequest(BaseModel):
    """Step 2 完成注册请求体。"""

    username: str = Field(
        ..., min_length=3, max_length=20, description="用户名（3-20 字符，仅字母数字下划线）"
    )
    password: str = Field(..., description="SHA256 双重哈希后的 64 字符 hex 字符串")
    email: str | None = Field(None, description="邮箱（可选）")

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        """仅允许字母、数字、下划线。"""
        import re
        if not re.fullmatch(r"[a-zA-Z0-9_]+", v):
            raise ValueError("用户名仅允许字母、数字和下划线")
        return v

    @field_validator("password")
    @classmethod
    def password_must_be_hex64(cls, v: str) -> str:
        """密码必须为 64 字符 SHA256 hex 字符串。"""
        import re
        if len(v) != 64 or not re.fullmatch(r"[a-fA-F0-9]{64}", v):
            raise ValueError("密码必须为 64 字符 SHA256 哈希值（hex）")
        return v
```

- [ ] **Step 5: 新增 `POST /register/complete` 端点**

在 `register_user` 端点之后（约行 394 附近）添加：

```python
# ---------------------------------------------------------------------------
# POST /users/register/complete — Step 2 完成注册
# ---------------------------------------------------------------------------

@router.post("/register/complete", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def complete_register(
    body: CompleteRegisterRequest,
    temp_user: dict = Depends(get_temp_user),
):
    """完成注册 Step 2：设置用户名和密码，返回正式 JWT token。

    认证：临时 token（purpose="register_complete"），15 分钟有效。
    验证用户名和邮箱唯一性后，写入 password/username/email。
    """
    user_uuid: str = temp_user["uuid"]

    async with get_session() as session:
        # 验证 username 唯一性
        existing = await UsersDAO.find_by_username(session, body.username)
        if existing and str(existing.uuid) != user_uuid:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="用户名已被使用",
            )

        # 验证 email 唯一性（若提供）
        if body.email:
            email_user = await UsersDAO.find_by_username_or_email(session, body.email)
            if email_user and str(email_user.uuid) != user_uuid:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="邮箱已被使用",
                )

    # 更新用户：设置密码、用户名、邮箱
    update_data: dict[str, Any] = {
        "password": body.password,
        "username": body.username,
    }
    if body.email:
        update_data["email"] = body.email

    updated_user = await UsersDAO().update(user_uuid, update_data)
    if updated_user is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="完成注册失败，用户不存在",
        )

    # 颁发正式 token
    access_token = create_access_token(subject=user_uuid)
    plaintext, token_hash = generate_refresh_token()
    await RefreshTokensDAO.create(user_uuid=user_uuid, token_hash=token_hash)

    custom_log("SUCCESS", f"[RegisterComplete] uuid={user_uuid} username={body.username} 注册完成")

    return {
        "access_token": access_token,
        "refresh_token": plaintext,
        "token_type": "bearer",
        "user": {
            "uuid": updated_user["uuid"],
            "nickname": updated_user.get("nickname"),
            "real_name": updated_user.get("real_name"),
            "username": updated_user.get("username"),
            "email": updated_user.get("email"),
            "class": updated_user.get("class"),
            "class_type": updated_user.get("class_type"),
            "role": updated_user.get("user_role"),
            "is_verified": updated_user.get("is_verified"),
            "status": updated_user.get("current_status"),
        },
    }
```

---

### Task 8: Users 模块 — `GET /me` + `DELETE /me`

**Files:**
- Modify: `modules/api/v1/users.py`

- [ ] **Step 1: 新增 `GET /me` 端点（从 auth.py 迁移）**

在 `update_profile` 端点之后（`PATCH /me/profile` 之后）添加：

```python
# ---------------------------------------------------------------------------
# GET /users/me — 完整用户信息
# ---------------------------------------------------------------------------

@router.get("/me", response_model=dict[str, Any])
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """返回当前用户的完整个人信息（非敏感字段）。

    注意：不从 Redis 缓存读取，直接从数据库获取最新数据。
    排除字段：password, id, other_info, deletion_scheduled_at, last_login_ip
    """
    user_uuid: str = current_user["uuid"]
    user = await UsersDAO().find_by_uuid(user_uuid)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在",
        )

    return {
        "uuid": user.get("uuid"),
        "username": user.get("username"),
        "email": user.get("email"),
        "avatar_url": user.get("avatar_url"),
        "nickname": user.get("nickname"),
        "real_name": user.get("real_name"),
        "class": user.get("class"),
        "class_type": user.get("class_type"),
        "joined_at": str(user.get("joined_at")) if user.get("joined_at") else None,
        "current_status": user.get("current_status"),
        "last_login_at": str(user.get("last_login_at")) if user.get("last_login_at") else None,
        "score": user.get("score"),
        "user_role": user.get("user_role"),
        "title": user.get("title"),
        "invited_by": user.get("invited_by"),
        "views": user.get("views"),
        "is_verified": user.get("is_verified"),
    }
```

- [ ] **Step 2: 新增 `DeleteAccountRequest` Pydantic 模型**

在 `CompleteRegisterRequest` 之后添加：

```python
class DeleteAccountRequest(BaseModel):
    """账号注销请求体 — 需密码确认。"""

    password: str = Field(..., description="SHA256 双重哈希后的 64 字符 hex 字符串")
```

- [ ] **Step 3: 新增 `DELETE /me` 端点**

在 `GET /me` 端点之后添加：

```python
# ---------------------------------------------------------------------------
# DELETE /users/me — 账号注销（30 天冷却期）
# ---------------------------------------------------------------------------

@router.delete("/me", response_model=dict[str, Any])
async def delete_account(
    body: DeleteAccountRequest,
    current_user: dict = Depends(get_current_user),
):
    """注销当前账号，进入 30 天冷却期。

    30 天内登录自动恢复；超期后由定时清理任务物理删除。
    需要密码确认。
    """
    user_uuid: str = current_user["uuid"]

    # 验证账号状态
    status_val = current_user.get("current_status")
    if status_val not in (None, "normal"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="账号状态异常，无法注销",
        )

    # 验证密码
    async with get_session() as session:
        stored_hash = await UsersDAO.find_password_hash(session, user_uuid)

    if not stored_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="账号未设置密码，无法验证身份",
        )

    if not verify_password(body.password, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="密码不正确",
        )

    # 设置冷却期
    deletion_time = datetime.now(timezone.utc) + timedelta(days=30)
    await UsersDAO().update(user_uuid, {
        "current_status": "pending_deletion",
        "deletion_scheduled_at": deletion_time,
    })

    # 撤销所有 refresh token，强制重新登录
    await RefreshTokensDAO.revoke_all_for_user(user_uuid)
    invalidate_user_cache(user_uuid)

    custom_log("SUCCESS", f"[DeleteAccount] uuid={user_uuid} 已进入注销冷却期，预定删除时间={deletion_time.isoformat()}")

    return {"message": "账号已进入注销冷却期，30天内登录可恢复"}
```

- [ ] **Step 4: 添加缺失的导入**

确保 `users.py` 顶部有以下导入（按顺序：stdlib → third-party → core → modules）：

- `from datetime import datetime, timedelta, timezone` — 补充 `timedelta`
- `from core.middleware.auth.dependencies import get_current_user, get_temp_user, invalidate_user_cache` — 补充 `invalidate_user_cache`

---

### Task 9: Users 模块 — 密码修改适配

**Files:**
- Modify: `modules/api/v1/users.py`

- [ ] **Step 1: 调整 `ChangePasswordRequest` 的 `new_password` 校验**

当前 `new_password` 的 `min_length=8, max_length=128` 对 64 字符 hex 仍然有效。但 `old_password` 的 `min_length=1` 太宽松。修改 `old_password`：

```python
old_password: str = Field(..., min_length=64, max_length=64, description="当前密码（64 字符 SHA256 hex）")
```

修改 `new_password`：

```python
new_password: str = Field(
    ..., min_length=64, max_length=64, description="新密码（64 字符 SHA256 hex）"
)
```

并添加 hex 校验 validator：

```python
@field_validator("old_password", "new_password")
@classmethod
def password_must_be_hex64(cls, v: str) -> str:
    """密码必须为 64 字符 SHA256 hex 字符串。"""
    import re
    if not re.fullmatch(r"[a-fA-F0-9]{64}", v):
        raise ValueError("密码必须为 64 字符 SHA256 哈希值（hex）")
    return v
```

移除旧的 `new_password_no_surrounding_spaces` validator（对 hex 字符串不再需要）。

- [ ] **Step 2: `change_password` 逻辑保持不变**

验证逻辑不变（旧密码验证、新旧不同检查、更新数据库、撤销 token）。底层 `verify_password` / `get_password_hash` 已通过 Task 2 桥接到 SHA256 直通方案，无需改动端点代码本身。

---

### Task 10: 定时清理模块 — `core/cron/`

**Files:**
- Create: `core/cron/__init__.py`
- Create: `core/cron/scheduler.py`
- Create: `core/cron/tasks/__init__.py`
- Create: `core/cron/tasks/cleanup_users.py`

- [ ] **Step 1: 创建 `core/cron/__init__.py`**

```python
"""定时任务模块 — 基于 apscheduler AsyncIOScheduler。

扩展方式：在 tasks/ 下新建文件，在 scheduler.py 中注册。
"""
```

- [ ] **Step 2: 创建 `core/cron/tasks/__init__.py`**

```python
"""定时任务包。"""
```

- [ ] **Step 3: 创建 `core/cron/tasks/cleanup_users.py`**

```python
"""清理过期注销账号任务 — 每小时执行一次。"""

from datetime import datetime, timezone

from sqlalchemy import select

from core.database.connection.pgsql import get_session
from core.database.dao.refresh_tokens import RefreshTokensDAO
from core.database.dao.users import User
from core.helper.CustomLog.index import custom_log


async def cleanup_expired_deletions() -> None:
    """清理所有冷却期已满的注销账号。

    查询条件：current_status = 'pending_deletion' AND deletion_scheduled_at <= now()
    操作：撤销所有 refresh token → 物理删除用户记录。
    """
    now = datetime.now(timezone.utc)

    # Step 1: 查找过期用户
    async with get_session() as session:
        result = await session.scalars(
            select(User).where(
                User.current_status == "pending_deletion",
                User.deletion_scheduled_at <= now,
            )
        )
        expired_users = result.all()

    if not expired_users:
        return

    expired_uuids = [str(u.uuid) for u in expired_users]

    # Step 2: 撤销所有 refresh token
    for uuid in expired_uuids:
        await RefreshTokensDAO.revoke_all_for_user(uuid)

    # Step 3: 物理删除用户
    async with get_session() as session:
        result = await session.scalars(
            select(User).where(User.uuid.in_(expired_uuids))
        )
        for user in result.all():
            await session.delete(user)
        await session.flush()

    custom_log("SUCCESS", f"[Cron] 清理过期注销账号: {len(expired_uuids)} 个")
```

- [ ] **Step 4: 创建 `core/cron/scheduler.py`**

```python
"""定时任务调度器 — 负责注册和启停所有定时任务。"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from core.helper.CustomLog.index import custom_log

scheduler = AsyncIOScheduler()


def start() -> None:
    """启动调度器并注册所有定时任务。"""
    from core.cron.tasks.cleanup_users import cleanup_expired_deletions

    scheduler.add_job(
        cleanup_expired_deletions,
        trigger="interval",
        hours=1,
        id="cleanup_expired_deletions",
        replace_existing=True,
    )

    scheduler.start()
    custom_log("SUCCESS", "[Cron] 定时任务调度器已启动")


def stop() -> None:
    """停止调度器。"""
    scheduler.shutdown(wait=False)
    custom_log("SUCCESS", "[Cron] 定时任务调度器已停止")
```

---

### Task 11: 服务启动集成 — `server.py`

**Files:**
- Modify: `server.py`

- [ ] **Step 1: 在 lifespan 中启停调度器**

修改 `lifespan` 函数，在 `redis_conn.start()` 之后、`yield` 之前启动调度器，在 `yield` 之后停止：

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    from sqlalchemy import text
    try:
        async with get_session() as session:
            await session.execute(text("SELECT 1"))
        custom_log("SUCCESS", "PostgreSQL 连接成功")
    except Exception as exc:
        custom_log("ERROR", f"PostgreSQL 连接失败: {exc}")
    redis_conn.start()

    # 启动定时任务调度器
    from core.cron.scheduler import start as start_scheduler, stop as stop_scheduler
    start_scheduler()

    yield

    # 停止定时任务调度器
    stop_scheduler()

    await dispose_engine()
    custom_log("SUCCESS", "PostgreSQL 连接已关闭")
    redis_conn.stop()
```

---

### Task 12: 依赖更新 — `requirements.txt`

**Files:**
- Modify: `requirements.txt`

- [ ] **Step 1: 添加 apscheduler 并移除不再需要的依赖**

在 `requirements.txt` 末尾添加：

```
apscheduler==3.11.1
```

可移除 `passlib[bcrypt]==1.7.4` 和 `bcrypt==4.3.0`（不再使用 bcrypt）。但考虑到其他模块可能间接依赖，保守做法是保留它们，后续统一清理。

- [ ] **Step 2: 安装新依赖**

```bash
pip install apscheduler==3.11.1
```

---

## 自检

1. **Spec 覆盖：**
   - §3 密码模块 → Task 1, 2
   - §4 两步注册 → Task 7
   - §5 登录改 JSON → Task 6
   - §6 用户信息 /me → Task 8
   - §7 账号注销 → Task 8
   - §8 数据库变更 → Task 4
   - §9 定时清理 → Task 10, 11
   - §3.3 hash.py 桥接 → Task 2
   - §4.4 临时 token 依赖 → Task 3, 5

2. **占位符扫描：** 无 TBD / TODO / "implement later" / "add appropriate error handling"。

3. **类型一致性：**
   - `create_temp_token(subject, purpose, expires_minutes)` — Task 3 定义，Task 7 调用
   - `get_temp_user` — Task 5 定义，Task 7 调用
   - `UsersDAO.find_by_username(session, username)` — Task 4 定义，Task 7 调用
   - `deletion_scheduled_at` — Task 4 ORM 定义，Task 6/8/10 使用
   - 所有函数签名在定义和使用处一致

4. **不修改文件确认：**
   - `modules/api/v1/admin.py` — ✓ 不修改（通过 hash.py 桥接自动适配）
   - `modules/api/v1/router.py` — ✓ 不修改（端点挂在已有 router 下）
   - `core/database/dao/refresh_tokens.py` — ✓ 不修改（现有 API 满足需求）
   - 测试文件 — ✓ 不修改
   - 文档 — ✓ 不修改
