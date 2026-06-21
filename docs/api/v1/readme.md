# API v1 接口文档

本文档描述 Tinder 后端 API `v1` 版本的所有公开接口。

所有接口路径均以 `/api/v1` 为前缀，服务器默认运行于 `http://localhost:1912`。

---

## 目录

- [通用约定](#通用约定)
- [Index — 系统信息](#index--系统信息)
- [Auth — 认证](#auth--认证)
  - [POST /auth/login](#post-authlogin)
  - [POST /auth/refresh](#post-authrefresh)
  - [POST /auth/logout](#post-authlogout)
- [Users — 用户](#users--用户)
  - [注册整体流程（三步）](#注册整体流程三步)
  - [POST /users/register/sheet/request](#post-usersregistersheetrequest)
  - [POST /users/register](#post-usersregister)
  - [POST /users/register/complete](#post-usersregistercomplete)
  - [GET /users/me](#get-usersme)
  - [PATCH /users/me/password](#patch-usersmepassword)
  - [PATCH /users/me/profile](#patch-usersmeprofile)
  - [DELETE /users/me](#delete-usersme)
- [Admin — 管理员](#admin--管理员)
  - [用户管理](#用户管理)
  - [注册题目管理](#注册题目管理)
- [错误码一览](#错误码一览)
- [Redis Key 规范](#redis-key-规范)
- [安全机制总结](#安全机制总结)

---

## 通用约定

| 项目 | 说明 |
|------|------|
| 数据格式 | 请求体与响应体均为 JSON（登录接口亦然） |
| 字符编码 | UTF-8 |
| 认证方式 | Bearer Token（JWT，HS256，Access Token 60 分钟有效期） |
| 时间格式 | ISO 8601（`YYYY-MM-DDTHH:MM:SS`） |
| 错误结构 | `{ "detail": "<错误描述>" }` |

### 密码说明

密码传输采用**双层哈希**机制：

1. 客户端将明文密码做 SHA256 哈希（64 字符 hex 字符串）
2. 服务端收到后使用 bcrypt 再次加密后存储
3. 所有涉及密码的接口字段均接收 64 字符 hex 字符串，**不接受明文密码**

### RBAC（角色）

权限强弱：`superadmin` > `songlist_editor` > `normal-user`。高级角色自动通过低级角色的权限检查。

- `superadmin` — 管理员，可访问所有管理接口
- `songlist_editor` — 歌单编辑者（当前仅供扩展，无独立端点）
- `normal-user` — 普通用户（注册默认角色）

---

## Index — 系统信息

路由前缀：`/`  
来源文件：`modules/index/index.py`

### GET /

**说明：** 健康检查接口，返回服务名称、当前时间和系统版本。

**认证：** 不需要

**成功响应 `200 OK`：**

```json
{
  "name": "Tinder",
  "system_time": "2026-06-21T12:00:00",
  "system_version": "macOS-15.6-arm64-arm-64bit"
}
```

---

## Auth — 认证

路由前缀：`/api/v1/auth`  
来源文件：`modules/api/v1/auth.py`

---

### POST /auth/login

**说明：** 使用用户名或邮箱 + SHA256 哈希密码登录，返回 Access Token + Refresh Token。

账号处于 `pending_deletion` 冷却期时，登录会自动将状态恢复为 `normal`。

**认证：** 不需要

**限流：** 每 IP 每分钟最多 20 次；每用户名每分钟最多 5 次（基于 Redis 计数器）。

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `username` | string | ✓ | 用户名或邮箱 |
| `password` | string | ✓ | SHA256 双重哈希后的 hex 字符串（64 字符） |

**请求示例：**

```json
{
  "username": "testuser",
  "password": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
}
```

**成功响应 `200 OK`：**

```json
{
  "access_token": "<JWT>",
  "refresh_token": "<plaintext-refresh-token>",
  "token_type": "bearer"
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `401 Unauthorized` | 用户不存在或密码错误 |
| `403 Forbidden` | 账号已被禁用/封禁/永久注销 |
| `429 Too Many Requests` | 登录尝试过于频繁（IP 级别或用户名级别） |

---

### POST /auth/refresh

**说明：** 使用 Refresh Token 换取新的 Access Token 和 Refresh Token（轮转机制）。

旧的 Refresh Token 会被吊销，返回全新的 token 对。

**认证：** 不需要（使用 Refresh Token 本身）

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `refresh_token` | string | ✓ | 登录时获得的 refresh_token 原文 |

**成功响应 `200 OK`：**

```json
{
  "access_token": "<new-JWT>",
  "refresh_token": "<new-plaintext-refresh-token>",
  "token_type": "bearer"
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `401 Unauthorized` | Refresh Token 无效、已吊销或用户已被禁用 |

---

### POST /auth/logout

**说明：** 登出当前设备，吊销 Refresh Token。Access Token 在有效期内自然失效，无需额外处理。

**认证：** 需要（Bearer Token）

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `refresh_token` | string | ✓ | 要吊销的 refresh_token 原文 |

**成功响应 `200 OK`：**

```json
{
  "message": "已登出"
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `401 Unauthorized` | Token 缺失、格式错误或已过期 |

---

## Users — 用户

路由前缀：`/api/v1/users`  
来源文件：`modules/api/v1/users.py`

---

### 注册整体流程（三步）

```
客户端                                    服务端
  │                                          │
  │── POST /users/register/sheet/request ──▶│  随机抽 5 道题，存入 Redis
  │◀─ { sheet_id, questions[] } ─────────────│  返回题目（不含答案）
  │                                          │
  │── POST /users/register ─────────────────▶│  1. IP 今日尝试 ≤ 10
  │   { nickname, real_name,                 │  2. real_name 今日尝试 ≤ 3
  │     classtype, class,                    │  3. sheet 存在且尝试 ≤ 3
  │     sheet_id, answers[] }                │  4. 答对 ≥ 3 道
  │                                          │  5. 无重复学生（姓名+班级）
  │◀─ { temp_token, user{} } ────────────────│  创建用户（password=NULL），颁发临时 token
  │                                          │
  │── POST /users/register/complete ────────▶│  1. 临时 token 校验（15 分钟有效）
  │   { username, password, email? }         │  2. 验证 username、email 唯一性
  │                                          │  3. 设置 password/username/email
  │◀─ { access_token, refresh_token, user } ─│  颁发正式 JWT
```

---

### POST /users/register/sheet/request

**说明：** 从 `register_questions` 表中随机抽取 5 道 `active` 状态的题目，生成一张问题表存入 Redis（TTL 24 小时），返回给客户端的数据**不含答案**。每个 IP 每天最多获取 4 张问题表。

**认证：** 不需要

**成功响应 `200 OK`：**

```json
{
  "sheet_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "questions": [
    { "uuid": "q-uuid-1", "question": "题目内容一" },
    { "uuid": "q-uuid-2", "question": "题目内容二" },
    { "uuid": "q-uuid-3", "question": "题目内容三" },
    { "uuid": "q-uuid-4", "question": "题目内容四" },
    { "uuid": "q-uuid-5", "question": "题目内容五" }
  ]
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `429 Too Many Requests` | IP 今日已获取 4 张问题表 |
| `500 Internal Server Error` | Redis 写入失败 |
| `503 Service Unavailable` | 题库中 active 题目不足 5 道，或 Redis 不可用 |

---

### POST /users/register

**说明：** 提交注册请求（注册 Step 1），携带个人信息、问题表 ID 和答案列表。通过校验后创建用户（`password=NULL`），颁发临时 token，供 Step 2 完成注册使用。

**认证：** 不需要

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 约束 | 说明 |
|------|------|------|------|------|
| `nickname` | string | ✓ | 1–50 字符，无控制字符 | 昵称 |
| `real_name` | string | ✓ | 1–50 字符，无控制字符 | 真实姓名 |
| `classtype` | string | ✓ | `"high-school"` 或 `"university"` | 学段 |
| `class` | string | ✓ | 1–50 字符，无控制字符 | 班级 |
| `sheet_id` | string | ✓ | 来自 sheet/request | 问题表 ID |
| `answers` | array | ✓ | 5 个元素 | 答案列表 |
| `answers[].question_uuid` | string | ✓ | | 对应题目的 uuid |
| `answers[].answer` | string | ✓ | 大小写不敏感 | 回答内容 |

**请求示例：**

```json
{
  "nickname": "小明",
  "real_name": "王小明",
  "classtype": "high-school",
  "class": "高一(1)班",
  "sheet_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "answers": [
    { "question_uuid": "q-uuid-1", "answer": "答案一" },
    { "question_uuid": "q-uuid-2", "answer": "答案二" },
    { "question_uuid": "q-uuid-3", "answer": "答案三" },
    { "question_uuid": "q-uuid-4", "answer": "答案四" },
    { "question_uuid": "q-uuid-5", "answer": "答案五" }
  ]
}
```

**校验流程：**

1. IP 当日注册尝试总次数 ≤ 10
2. `real_name` 当日注册尝试次数 ≤ 3
3. `sheet_id` 对应的问题表在 Redis 中存在，且该表尝试次数 ≤ 3
4. 5 道题中至少 3 道答对（大小写不敏感，去除首尾空白）
5. 数据库中不存在相同 `real_name + class` 的学生

> **注意：** 步骤 1–3 的计数器在校验答案**之前**递增，防止暴力枚举。注册成功后问题表从 Redis 删除，不可重复使用。

**成功响应 `201 Created`：**

```json
{
  "temp_token": "<JWT>",
  "token_type": "bearer",
  "expires_in": 900,
  "user": {
    "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "nickname": "小明",
    "real_name": "王小明",
    "class": "高一(1)班",
    "class_type": "high-school",
    "role": "normal-user",
    "is_verified": false,
    "status": "normal"
  }
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `400 Bad Request` | 问题表不存在或已过期 |
| `400 Bad Request` | 问题表尝试次数已达上限（3 次） |
| `400 Bad Request` | 答对题目数不足 3 道 |
| `409 Conflict` | 相同真实姓名（`real_name`）+ 班级的学生已存在 |
| `422 Unprocessable Entity` | 请求体字段格式错误（如 classtype 非法） |
| `429 Too Many Requests` | IP 今日注册尝试次数已达上限（10 次） |
| `429 Too Many Requests` | 该姓名今日注册尝试次数已达上限（3 次） |
| `500 Internal Server Error` | 数据库写入失败 |
| `503 Service Unavailable` | Redis 不可用 |

---

### POST /users/register/complete

**说明：** 完成注册（注册 Step 2），设置用户名和密码，返回正式 JWT token。

**认证：** 需要临时 Bearer Token（来自 `/users/register`，`purpose="register_complete"`，15 分钟有效）

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 约束 | 说明 |
|------|------|------|------|------|
| `username` | string | ✓ | 3–20 字符，仅字母数字下划线 | 登录用户名（全局唯一） |
| `password` | string | ✓ | 64 字符 SHA256 hex | SHA256 双重哈希后的密码 |
| `email` | string \| null | — | 有效邮箱格式 | 邮箱（可选，提供则检查唯一性） |

**请求示例：**

```json
{
  "username": "xiaoming",
  "password": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "email": "xiaoming@example.com"
}
```

**成功响应 `201 Created`：**

```json
{
  "access_token": "<JWT>",
  "refresh_token": "<plaintext-refresh-token>",
  "token_type": "bearer",
  "user": {
    "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "nickname": "小明",
    "real_name": "王小明",
    "username": "xiaoming",
    "email": "xiaoming@example.com",
    "class": "高一(1)班",
    "class_type": "high-school",
    "role": "normal-user",
    "is_verified": false,
    "status": "normal"
  }
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `401 Unauthorized` | 临时 Token 缺失、无效或已过期 |
| `409 Conflict` | 用户名或邮箱已被使用 |
| `422 Unprocessable Entity` | 请求体校验失败（如 username 格式非法） |
| `500 Internal Server Error` | 数据库更新失败 |

---

### GET /users/me

**说明：** 返回当前用户的完整个人信息（非敏感字段）。直接从数据库获取最新数据，不从 Redis 缓存读取。排除字段：`password`、`id`、`other_info`、`deletion_scheduled_at`、`last_login_ip`。

**认证：** 需要（Bearer Token）

**成功响应 `200 OK`：**

```json
{
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "username": "xiaoming",
  "email": "xiaoming@example.com",
  "avatar_url": null,
  "nickname": "小明",
  "real_name": "王小明",
  "class": "高一(1)班",
  "class_type": "high-school",
  "joined_at": "2026-06-01 12:00:00",
  "current_status": "normal",
  "last_login_at": "2026-06-21 10:00:00",
  "score": 0,
  "user_role": "normal-user",
  "title": null,
  "invited_by": null,
  "views": 0,
  "is_verified": false
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `401 Unauthorized` | Token 缺失、格式错误或已过期 |
| `404 Not Found` | 用户不存在 |

---

### PATCH /users/me/password

**说明：** 已登录用户修改自己的账号密码，必须提供当前旧密码进行身份验证。密码变更后自动撤销该用户的所有 Refresh Token，强制所有设备重新登录。如果提供了当前设备的 `refresh_token`，将额外吊销该设备的 token。

**认证：** 需要（Bearer Token）

**限流：** 每个用户每天最多尝试修改密码 10 次（由 Redis 记录）。

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 约束 | 说明 |
|------|------|------|------|------|
| `old_password` | string | ✓ | 64 字符 SHA256 hex | 当前密码 |
| `new_password` | string | ✓ | 64 字符 SHA256 hex | 新密码 |
| `refresh_token` | string \| null | — | | 当前设备的 Refresh Token（可选，提供后将额外吊销该设备） |

**请求示例：**

```json
{
  "old_password": "a1b2c3d4...",
  "new_password": "e5f6a1b2...",
  "refresh_token": "xxx-yyy-zzz"
}
```

**成功响应 `200 OK`：**

```json
{
  "message": "密码修改成功"
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `400 Bad Request` | 旧密码不正确 |
| `400 Bad Request` | 新密码与旧密码相同 |
| `400 Bad Request` | 当前账号未设置密码 |
| `401 Unauthorized` | Token 缺失、格式错误或已过期 |
| `403 Forbidden` | 账号状态异常（如被封禁） |
| `404 Not Found` | 用户不存在 |
| `422 Unprocessable Entity` | 请求体校验失败 |
| `429 Too Many Requests` | 今日修改密码次数已达上限（10 次） |
| `500 Internal Server Error` | 数据库更新失败 |

---

### PATCH /users/me/profile

**说明：** 已登录用户修改自己的个人信息。支持修改昵称（`nickname`）、真实姓名（`real_name`）和班级（`class`），所有字段均为可选，但至少提供一个。若变更了 `real_name` 或 `class`，系统会检查数据库中是否存在同名同班级的其他用户。

**认证：** 需要（Bearer Token）

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 约束 | 说明 |
|------|------|------|------|------|
| `nickname` | string \| null | — | 1–50 字符，无控制字符 | 新昵称 |
| `real_name` | string \| null | — | 1–50 字符，无控制字符 | 新真实姓名 |
| `class` | string \| null | — | 1–50 字符，无控制字符 | 新班级 |

> 三个字段至少需要提供一个非 `null` 值。

**请求示例（同时修改姓名和班级）：**

```json
{
  "real_name": "李小明",
  "class": "高二(2)班"
}
```

**成功响应 `200 OK`：**

```json
{
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "nickname": "新昵称",
  "real_name": "王小明",
  "class": "高一(1)班",
  "class_type": "high-school",
  "role": "normal-user",
  "is_verified": false,
  "status": "normal"
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `401 Unauthorized` | Token 缺失、格式错误或已过期 |
| `403 Forbidden` | 账号状态异常（如被封禁） |
| `404 Not Found` | 用户不存在 |
| `409 Conflict` | 修改后的真实姓名 + 班级与数据库中其他用户冲突 |
| `422 Unprocessable Entity` | 请求体字段格式错误（如包含控制字符、全部字段为 null） |
| `500 Internal Server Error` | 数据库更新失败 |

---

### DELETE /users/me

**说明：** 注销当前账号，进入 30 天冷却期。冷却期内登录可自动恢复账号（详见 `/auth/login`）；超期后由定时清理任务物理删除。需要密码确认。操作成功后撤销所有 Refresh Token。

**认证：** 需要（Bearer Token）

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `password` | string | ✓ | SHA256 双重哈希后的 64 字符 hex 字符串 |

**成功响应 `200 OK`：**

```json
{
  "message": "账号已进入注销冷却期，30天内登录可恢复"
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `400 Bad Request` | 密码不正确或账号未设置密码 |
| `401 Unauthorized` | Token 缺失、格式错误或已过期 |
| `403 Forbidden` | 账号状态异常 |
| `404 Not Found` | 用户不存在 |

---

## Admin — 管理员

路由前缀：`/api/v1/admin`  
来源文件：`modules/api/v1/admin.py`

所有管理接口均需满足：
1. **认证：** Bearer Token（JWT）
2. **RBAC：** `MinRoleChecker(Role.SUPERADMIN)` — 仅 `superadmin` 角色可访问
3. **高危操作：** 删除用户等操作还需额外校验超级密码 `SUPER_PASSWORD`

---

### 用户管理

#### GET /admin/users

**说明：** 分页搜索用户列表，支持关键词模糊搜索、状态筛选、角色筛选。

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `limit` | integer | — | 100 | 每页数量（1–500） |
| `offset` | integer | — | 0 | 偏移量 |
| `keyword` | string | — | | 搜索关键词（匹配用户名/邮箱/昵称/真实姓名） |
| `status` | string | — | | 按状态筛选：`normal` / `disabled` / `banned` / `pending_deletion` |
| `role` | string | — | | 按角色筛选：`superadmin` / `songlist_editor` / `normal-user` |

#### GET /admin/users/total

**说明：** 获取用户总数（支持可选筛选）。参数同 `GET /admin/users` 中的 `keyword`、`status`、`role`。

```json
{ "total": 100 }
```

#### GET /admin/users/stats

**说明：** 用户统计：总数 + 各状态分布。

#### POST /admin/users

**说明：** 创建用户。可写入 users 表的部分字段；若包含 `password` 会被自动 hash 后写入；若未提供 `uuid` 则自动生成。

#### PATCH /admin/users/{user_uuid}

**说明：** 编辑用户信息（含角色、状态）。若包含 `password` 会被自动 hash 后写入。

#### DELETE /admin/users/{user_uuid}

**说明：** 删除单个用户。**高危操作**，需要超级密码。

**安全限制：**
1. 必须提供 `super_password` 字段（在请求体中）
2. 不能删除当前登录的管理员自己
3. 不能删除同级的超级管理员
4. 系统中仅剩 2 个超级管理员时，不能再删除其中任何一个

**请求体：**

```json
{
  "super_password": "<SUPER_PASSWORD>"
}
```

#### DELETE /admin/users/batch

**说明：** 批量删除用户。**高危操作**，需要超级密码。

**安全限制：**
1. 必须提供超级密码
2. 不能包含当前登录的管理员自己
3. 不能包含 `superadmin` 角色

**请求体：**

```json
{
  "uuids": ["uuid-1", "uuid-2"],
  "super_password": "<SUPER_PASSWORD>"
}
```

**成功响应：**

```json
{ "deleted": 2 }
```

#### POST /admin/users/{user_uuid}/disable

**说明：** 禁用用户（状态设为 `disabled`）。

#### POST /admin/users/{user_uuid}/enable

**说明：** 启用用户（状态设为 `normal`）。

#### POST /admin/users/{user_uuid}/ban

**说明：** 封禁用户（状态设为 `banned`）。

#### POST /admin/users/{user_uuid}/unban

**说明：** 解除封禁（状态设为 `normal`）。

---

### 注册题目管理

#### GET /admin/questions/stats

**说明：** 题目统计（按题型分布）。

```json
{
  "total": 50,
  "choice": 20,
  "true_false": 15,
  "fill_blank": 15
}
```

#### GET /admin/questions

**说明：** 分页搜索题目列表。

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `limit` | integer | — | 100 | 每页数量（1–500） |
| `offset` | integer | — | 0 | 偏移量 |
| `keyword` | string | — | | 模糊匹配题目内容 |
| `type` | string | — | | 按题型筛选：`choice` / `true_false` / `fill_blank` |
| `status` | string | — | | 按状态筛选：`active` / `inactive` |

#### GET /admin/questions/total

**说明：** 获取题目总数（支持可选筛选）。参数同 `GET /admin/questions`。

#### POST /admin/questions

**说明：** 创建题目。自动设置 `uuid`、`created_by`（当前管理员）、`current_status="active"`。`options` 字段会自动 JSON 序列化存储。

**请求体：**

| 字段 | 类型 | 必填 | 约束 | 说明 |
|------|------|------|------|------|
| `question` | string | ✓ | 1–500 字符 | 题目内容 |
| `question_type` | string | ✓ | `"choice"` / `"true_false"` / `"fill_blank"` | 题目类型 |
| `answer` | string | ✓ | 1–200 字符 | 正确答案 |
| `options` | array\[string] | — | 选择题至少 2 个不重复选项，答案必须在选项中 | 选择题选项（仅 choice 类型需要） |
| `question_level` | string | — | | 题目难度 |

**校验规则：**
- `choice` 类型：`options` 至少 2 个不重复选项，`answer` 必须在 `options` 中
- `true_false` 类型：`answer` 只能为 `true` 或 `false`（大小写不敏感）

#### PATCH /admin/questions/{question_uuid}

**说明：** 编辑题目。所有字段可选，至少提供一个。校验规则同创建。

#### PATCH /admin/questions/{question_uuid}/status

**说明：** 单题切换状态。

**请求体：**

```json
{
  "status": "active"
}
```

`status` 取值：`"active"` 或 `"inactive"`。

#### DELETE /admin/questions/{question_uuid}

**说明：** 删除单题。

#### POST /admin/questions/batch-delete

**说明：** 批量删除题目。

**请求体：**

```json
{
  "uuids": ["uuid-1", "uuid-2"]
}
```

#### PATCH /admin/questions/batch-status

**说明：** 批量切换题目状态（active/inactive）。

**请求体：**

```json
{
  "uuids": ["uuid-1", "uuid-2"],
  "status": "inactive"
}
```

---

## 错误码一览

| HTTP 状态码 | 含义 | 常见场景 |
|-------------|------|---------|
| `200 OK` | 请求成功 | GET / PATCH / DELETE 类接口 |
| `201 Created` | 资源创建成功 | POST /users/register、POST /admin/questions |
| `400 Bad Request` | 请求参数或业务逻辑错误 | 问题表无效、答题未通过、密码错误、未提供修改字段 |
| `401 Unauthorized` | 认证失败 | Token 缺失、无效或过期 |
| `403 Forbidden` | 权限或安全限制 | 账号被封禁、角色不足、超级密码错误、不能删除自己 |
| `404 Not Found` | 资源不存在 | 用户不存在、题目不存在 |
| `409 Conflict` | 资源冲突 | 重复学生、用户名或邮箱已被使用 |
| `422 Unprocessable Entity` | 请求体校验失败 | 字段类型/格式/长度不符合约束 |
| `429 Too Many Requests` | 频率限制 | IP/姓名/登录/密码修改今日或每分钟尝试次数过多 |
| `500 Internal Server Error` | 服务器内部错误 | 数据库/Redis 写入失败 |
| `503 Service Unavailable` | 服务暂时不可用 | Redis 断连、题库不足 |

---

## Redis Key 规范

### 注册模块

| Key 格式 | 值类型 | 用途 | TTL |
|----------|--------|------|-----|
| `reg:qsheet:{sheet_id}` | JSON string | 问题表完整数据（含答案，仅服务端使用） | 24h |
| `reg:qsheet_atm:{sheet_id}` | integer | 该问题表的答题尝试次数 | 24h |
| `reg:ip_atm:{ip}:{YYYY-MM-DD}` | integer | IP 当日注册尝试次数 | 24h |
| `reg:name_atm:{name_hex}:{YYYY-MM-DD}` | integer | 同名用户当日注册尝试次数 | 24h |
| `reg:ip_sheets:{ip}:{YYYY-MM-DD}` | integer | IP 当日问题表获取次数 | 24h |

> `name_hex` 是将 `real_name` 字符串以 UTF-8 编码后转为十六进制字符串，用于避免特殊字符污染 Redis key。

### 登录限流

| Key 格式 | 值类型 | 用途 | TTL |
|----------|--------|------|-----|
| `login_atm:ip:{ip}:min` | integer | IP 每分钟登录尝试次数 | 60s |
| `login_atm:un:{username}:min` | integer | 用户名每分钟登录尝试次数 | 60s |

### 用户缓存

| Key 格式 | 值类型 | 用途 | TTL |
|----------|--------|------|-----|
| `auth:user:{uuid}` | JSON string | 用户认证信息缓存 | 60s |

### 密码修改限流

| Key 格式 | 值类型 | 用途 | TTL |
|----------|--------|------|-----|
| `user:pwd_chg:{user_uuid}:{YYYY-MM-DD}` | integer | 用户当日修改密码尝试次数 | 24h |

---

## 安全机制总结

| 层面 | 措施 |
|------|------|
| **密码存储** | 客户端 SHA256 哈希 → 服务端 bcrypt 哈希，双重保护 |
| **JWT 认证** | HS256 签名，Access Token 60 分钟有效期，Refresh Token 轮转机制 |
| **登录限流** | Redis 计数器：每 IP 每分钟 20 次 + 每用户名每分钟 5 次 |
| **注册限流** | IP 每日 10 次 + 姓名每日 3 次 + 每问题表 3 次尝试 |
| **密码修改限流** | 每用户每日 10 次 |
| **问题表获取限流** | 每 IP 每日 4 张 |
| **防火墙 (Firewall)** | IP 封禁 + 速率限制 + 爬虫检测 + 攻击特征检测（XSS/SQLi/路径遍历/SSRF） |
| **RBAC 权限** | 三级角色体系，最小权限原则 |
| **超级密码** | 高危操作（删除用户）需额外校验超级密码，独立于 JWT 认证 |
| **Refresh Token 轮转** | 每次 refresh 吊销旧 token、颁发新 token；密码变更时撤销全部 Refresh Token |
| **账号注销冷却** | 30 天冷却期，期内登录自动恢复，期满物理删除 |
| **输入校验** | Pydantic 模型层校验（长度、格式、控制字符拦截等） |
| **应答计数器前置递增** | 注册校验中，速率计数器在校验答案前递增，防止暴力枚举正确答案 |
