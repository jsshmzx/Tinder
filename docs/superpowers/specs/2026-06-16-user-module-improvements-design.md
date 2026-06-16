# 用户模块改进 — 设计规格

**日期:** 2026-06-16
**状态:** 已确认

---

## 1. 概述

对用户模块进行以下改进：

1. **密码哈希切换** — 从 bcrypt（服务端单向）改为客户端 SHA256 双重哈希，服务端直接存储和比对
2. **注册流程完善** — 两步注册：答题验证 → 临时 token → 设置密码 + 用户名
3. **登录改为 JSON** — 移除 OAuth2 表单，使用 JSON body
4. **用户信息增强** — `/me` 移到 users 路由，返回完整个人信息
5. **账号注销** — 30 天冷却期模式，需密码确认
6. **定时清理模块** — 独立 `core/cron/` 模块，清理过期注销账号

当前项目开发阶段，数据库无用户，**不需要**渐进式迁移和旧格式兼容。

---

## 2. API 汇总

| 方法 | 端点 | 认证 | 说明 |
|------|------|------|------|
| POST | `/api/v1/auth/login` | 无 | JSON 登录 |
| POST | `/api/v1/auth/refresh` | 无 | 刷新 token |
| POST | `/api/v1/auth/logout` | JWT | 注销 token |
| GET | `/api/v1/users/me` | JWT | 完整用户信息 |
| PATCH | `/api/v1/users/me/password` | JWT | 修改密码 |
| PATCH | `/api/v1/users/me/profile` | JWT | 修改资料 |
| DELETE | `/api/v1/users/me` | JWT | 账号注销（30 天冷却期） |
| POST | `/api/v1/users/register/sheet/request` | 无 | 生成答题卡 |
| POST | `/api/v1/users/register` | 无 | 答题验证，返回临时 token |
| POST | `/api/v1/users/register/complete` | 临时 token | 设密码 + 用户名，返回正式 token |

---

## 3. 密码模块 — `core/security/password.py`

### 3.1 哈希算法

```
hash_password(password: str) -> str
  - 输入: 客户端传来的 SHA256(SHA256(明文)) 的 hex 字符串（64 字符）
  - 输出: 直接返回 hex 字符串，不再额外哈希
  - 服务端不接触明文，直接存储和比对
```

### 3.2 验证

```
verify_password(password: str, stored_hash: str) -> bool
  - 直接字符串比较
  - 常量时间比对（防止 timing attack）
```

### 3.3 `hash.py` 处理

- 保留 `get_password_hash`、`verify_password` 函数签名
- 内部改为调用 `password.py`
- admin 模块继续调用 `hash.py`，但逻辑变为接收 SHA256 双重哈希 → 直接存储

---

## 4. 两步注册

### 4.1 Step 1a: 获取答题卡

`POST /api/v1/users/register/sheet/request`

- 无认证
- 速率限制：每 IP 每天 4 次（现有逻辑不变）
- 返回 `{ sheet_id, questions: [{ uuid, question }] }`

### 4.2 Step 1b: 提交答题

`POST /api/v1/users/register`

- 无认证
- 速率限制：每 IP 每天 10 次，每姓名每天 3 次，每答题卡 3 次（现有逻辑不变）
- 验证通过 → 创建用户（`password = NULL`）→ 颁发临时 token

**临时 token 设计：**
- JWT，payload: `{ sub: user_uuid, purpose: "register_complete", exp: 15min }`
- 仅可用于 Step 2，不可访问其他 API

### 4.3 Step 2: 完成注册

`POST /api/v1/users/register/complete`

```
Authorization: Bearer <temp_token>

Request: {
  username: str (3-20, [a-zA-Z0-9_]),
  password: str (64 字符 hex, SHA256 双重哈希),
  email?: str | None
}

Response: 201 {
  access_token: str,
  refresh_token: str,
  token_type: "bearer",
  user: { uuid, nickname, real_name, username, email, class, class_type, role, is_verified, status }
}
```

验证逻辑：
1. 解码临时 token → 提取 user_uuid
2. 验证 username 唯一性
3. 验证 email 唯一性（若提供）
4. 设置 password、username、email
5. 密码直接存入（SHA256 双重哈希 hex）
6. 返回正式 JWT access_token + refresh_token

### 4.4 临时 token 认证依赖

`core/middleware/auth/dependencies.py` 新增 `get_temp_user`：

```python
async def get_temp_user(credentials) -> dict:
    # 解码 JWT
    # 验证 payload.purpose == "register_complete"
    # 查 Redis 缓存 → 查 DB
    # 返回 user dict
```

与 `get_current_user` 区别：不检查 role，仅验证 token 有效且 purpose 匹配。

---

## 5. 登录 — `POST /api/v1/auth/login`

### 5.1 请求格式

改为 JSON body（不再使用 OAuth2PasswordRequestForm）：

```json
{
  "username": "demo_user",
  "password": "<64 char hex: SHA256(SHA256(明文))>"
}
```

### 5.2 验证逻辑

1. 按 username 或 email 查找用户
2. 直接比较 `user.password` 与请求中的 password hex
3. 检查 `current_status`：
   - `disabled` / `banned` → 拒绝
   - `pending_deletion` → 检查冷却期（见下文 7.3）
   - `normal` / `None` → 允许
4. 更新 `last_login_at`、`last_login_ip`
5. 返回 `{ access_token, refresh_token, token_type }`

### 5.3 速率限制

现有限制保持不变：

| 维度 | 限制 |
|------|------|
| 每 IP 每分钟 | 20 次 |
| 每用户名每分钟 | 5 次 |

---

## 6. 用户信息 — `GET /api/v1/users/me`

从 `auth.py` 移动到 `users.py`（`/auth/me` → `/users/me`）

- 认证：JWT（`get_current_user`）
- 缓存：不读 Redis 缓存，直接从 DB 获取最新数据
- 返回：完整用户信息（所有非敏感字段）

**返回字段：**
```
uuid, username, email, avatar_url, nickname, real_name, class, class_type,
joined_at, current_status, last_login_at, score, user_role, title,
invited_by, views, is_verified
```

**排除字段：** password, id, other_info, deletion_scheduled_at, last_login_ip

---

## 7. 账号注销 — `DELETE /api/v1/users/me`

### 7.1 请求

```
Authorization: Bearer <access_token>

Request: {
  password: str (64 字符 hex, SHA256 双重哈希)
}
```

### 7.2 处理逻辑

1. `get_current_user` 获取用户
2. 验证 `current_status` 为 `normal` 或 `None`
3. 验证密码（SHA256 双重哈希比对）
4. 验证通过 → 设置 `current_status = "pending_deletion"`
5. 设置 `deletion_scheduled_at = now + 30天`
6. 撤销该用户所有 refresh tokens
7. 返回 `{ message: "账号已进入注销冷却期，30天内可登录恢复" }`

### 7.3 冷却期内恢复

登录时（`POST /auth/login`）额外逻辑：

```
密码验证通过
→ 若 current_status == "pending_deletion":
  → 若 deletion_scheduled_at > now:
    → 恢复 current_status = "normal"
    → 清空 deletion_scheduled_at = NULL
    → 正常登录（返回 tokens）
  → 否则:
    → 返回 403 "账号已永久注销"
```

---

## 8. 数据库变更

### 8.1 新增列

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS deletion_scheduled_at TIMESTAMP NULL;
```

### 8.2 迁移文件

- 文件: `core/database/migrations/SQL/alter_users_add_deletion_scheduled_at.sql`
- 注册到 `core/database/migrations/migration_history.py`

---

## 9. 定时清理 — `core/cron/`

### 9.1 模块结构

```
core/cron/
├── __init__.py
├── scheduler.py          # 调度器，负责注册和启停所有任务
└── tasks/
    ├── __init__.py
    └── cleanup_users.py  # 清理过期注销账号
```

### 9.2 调度器设计

- 使用 `apscheduler` + `AsyncIOScheduler`
- `scheduler.py` 提供 `start()` / `stop()` 函数
- `server.py` 启动时调用 `scheduler.start()`
- 每个任务定义时基（interval）和执行函数

### 9.3 清理任务

- **任务**: `cleanup_users.py`
- **频率**: 每小时
- **逻辑**:
  1. 查询 `current_status = 'pending_deletion' AND deletion_scheduled_at <= now()`
  2. 逐条删除用户 → 撤销所有 refresh tokens
  3. `custom_log` 记录清理数量

### 9.4 扩展预留

- 新增定时任务只需在 `tasks/` 下新建文件，在 `scheduler.py` 中注册
- 不修改 `scheduler.py` 的核心调度逻辑

---

## 10. 文件变更清单

### 新增

| 文件 | 说明 |
|------|------|
| `core/security/password.py` | SHA256 双重哈希 + 验证 |
| `core/cron/__init__.py` | 定时任务模块入口 |
| `core/cron/scheduler.py` | 调度器 |
| `core/cron/tasks/__init__.py` | 任务包入口 |
| `core/cron/tasks/cleanup_users.py` | 清理过期注销账号 |
| `core/database/migrations/SQL/alter_users_add_deletion_scheduled_at.sql` | DB 迁移 |

### 修改

| 文件 | 说明 |
|------|------|
| `core/security/hash.py` | 桥接到 `password.py` |
| `modules/api/v1/auth.py` | 登录改 JSON + /me 移除 |
| `modules/api/v1/users.py` | 新增注册完成 + 注销 + /me 迁入 |
| `modules/api/v1/router.py` | 注册新路由 |
| `core/middleware/auth/dependencies.py` | 新增 `get_temp_user` |
| `core/database/migrations/migration_history.py` | 追加新迁移 |
| `core/database/dao/users.py` | `deletion_scheduled_at` 列 |
| `server.py` | 启动定时调度器 |

### 不修改

| 内容 | 原因 |
|------|------|
| admin 模块 | 管理员逻辑暂不动 |
| `other_info` JSONB | 暂不开放 |
| 密码重置 / 邮箱验证 | 本期不做 |
| 头像 | 本期不做 |
| 测试文件 | 后续统一处理 |
| 文档 | 后续统一处理 |

---

## 11. 自检

- [x] 无 "TBD"、"TODO" 或未完成的段落
- [x] API 汇总与各部分描述一致
- [x] 每个端点有明确的认证方式、请求格式、响应格式
- [x] 密码方案单一（SHA256 双重哈希），无兼容包袱
- [x] 定时清理独立模块，可扩展
- [x] 冷却期恢复路径已定义（登录时自动处理）
- [x] 文件变更清单覆盖所有改动
