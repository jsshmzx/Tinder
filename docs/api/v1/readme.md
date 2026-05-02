# API v1 接口文档

本文档描述 Tinder 后端 API `v1` 版本的所有公开接口。

所有接口路径均以 `/api/v1` 为前缀，服务器默认运行于 `http://localhost:1912`。

---

## 目录

- [通用约定](#通用约定)
- [Auth — 认证](#auth--认证)
  - [POST /auth/login](#post-authlogin)
  - [GET /auth/me](#get-authme)
- [Users — 用户](#users--用户)
  - [GET /users/register/questions](#get-usersregisterquestions)
  - [POST /users/register](#post-usersregister)
  - [PATCH /users/me/password](#patch-usersmepassword)
  - [PATCH /users/me/profile](#patch-usersmeprofile)
- [错误码一览](#错误码一览)
- [注册模块 Redis Key 规范](#注册模块-redis-key-规范)

---

## 通用约定

| 项目 | 说明 |
|------|------|
| 数据格式 | 请求体与响应体均为 JSON |
| 字符编码 | UTF-8 |
| 认证方式 | Bearer Token（JWT，HS256，7 天有效期） |
| 时间格式 | ISO 8601（`YYYY-MM-DDTHH:MM:SSZ`） |
| 错误结构 | `{ "detail": "<错误描述>" }` |

---

## Auth — 认证

路由前缀：`/api/v1/auth`  
来源文件：`modules/api/v1/auth.py`

---

### POST /auth/login

**说明：** 使用用户名或邮箱 + 密码登录，返回 JWT access token。

**认证：** 不需要

**请求：** `application/x-www-form-urlencoded`（OAuth2 表单格式）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `username` | string | ✓ | 用户名或邮箱 |
| `password` | string | ✓ | 明文密码 |

**成功响应 `200 OK`：**

```json
{
  "access_token": "<JWT>",
  "token_type": "bearer"
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `401 Unauthorized` | 用户不存在或密码错误 |

---

### GET /auth/me

**说明：** 返回当前登录用户的基本信息。

**认证：** 需要（Bearer Token）

**成功响应 `200 OK`：**

```json
{
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "real_name": "张三",
  "role": "normal-user"
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

### 注册整体流程

```
客户端                              服务端
  │                                    │
  │── GET /users/register/questions ──▶│  随机抽 5 道题，存入 Redis
  │◀─ { sheet_id, questions[] } ───────│  返回题目（不含答案）
  │                                    │
  │── POST /users/register ───────────▶│  1. IP 今日尝试 ≤ 10
  │   { nickname, real_name,           │  2. real_name 今日尝试 ≤ 3
  │     classtype, class,              │  3. sheet 存在且尝试 ≤ 3
  │     sheet_id, answers[] }          │  4. 答对 ≥ 3 道
  │                                    │  5. 无重复学生（姓名+班级）
  │◀─ { access_token, user{} } ────────│  写入 DB，返回 JWT
```

---

### GET /users/register/questions

**说明：** 从 `register_questions` 表中随机抽取 5 道 `active` 状态的题目，生成一张问题表存入 Redis（TTL 24 小时），返回给客户端的数据**不含答案**。

每个 IP 每天最多获取 **4 张**问题表（允许换题最多 3 次）。

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
| `503 Service Unavailable` | 题库中 active 题目不足 5 道，或 Redis 不可用 |

---

### POST /users/register

**说明：** 提交注册请求，携带个人信息、问题表 ID 和答案列表。

**认证：** 不需要

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 约束 | 说明 |
|------|------|------|------|------|
| `nickname` | string | ✓ | 1–50 字符，无控制字符 | 昵称 |
| `real_name` | string | ✓ | 1–50 字符，无控制字符 | 真实姓名 |
| `classtype` | string | ✓ | `"high-school"` 或 `"university"` | 学段 |
| `class` | string | ✓ | 1–50 字符，无控制字符 | 班级 |
| `sheet_id` | string | ✓ | 来自 GET /users/register/questions | 问题表 ID |
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
4. 5 道题中至少 **3 道**答对（大小写不敏感，去除首尾空白）
5. 数据库中不存在相同 `real_name + class` 的学生

> **注意：** 步骤 1–3 的计数器在校验答案**之前**递增，防止暴力枚举。注册成功后问题表从 Redis 删除，不可重复使用。

**成功响应 `201 Created`：**

```json
{
  "access_token": "<JWT>",
  "token_type": "bearer",
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

**写入数据库的默认值：**

| 字段 | 默认值 |
|------|--------|
| `user_role` | `"normal-user"` |
| `is_verified` | `false` |
| `current_status` | `"normal"` |
| 其他字段（`password`、`email` 等） | `null` |

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
| `503 Service Unavailable` | Redis 不可用 |

---

### PATCH /users/me/password

**说明：** 已登录用户修改自己的账号密码，必须提供当前旧密码进行身份验证。

**认证：** 需要（Bearer Token）

**限流：** 每个用户每天最多尝试修改密码 **10 次**（由 Redis 记录，不受 Redis 不可用影响——Redis 不可用时跳过限流）。

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 约束 | 说明 |
|------|------|------|------|------|
| `old_password` | string | ✓ | 非空 | 当前密码 |
| `new_password` | string | ✓ | 8–128 字符，首尾无空格 | 新密码 |

**请求示例：**

```json
{
  "old_password": "OldPassword123",
  "new_password": "NewPassword456"
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
| `400 Bad Request` | 当前账号未设置密码（注册时未设置，无法通过旧密码验证） |
| `401 Unauthorized` | Token 缺失、格式错误或已过期 |
| `403 Forbidden` | 账号状态异常（如已被封禁） |
| `404 Not Found` | 用户不存在（通常不应出现） |
| `422 Unprocessable Entity` | 请求体字段格式错误（如新密码不足 8 位、首尾有空格） |
| `429 Too Many Requests` | 今日修改密码次数已达上限（10 次） |
| `500 Internal Server Error` | 数据库更新失败 |

---

### PATCH /users/me/profile

**说明：** 已登录用户修改自己的个人信息。目前支持修改昵称（`nickname`）、真实姓名（`real_name`）和班级（`class`），所有字段均为可选，但**至少提供一个**。

若变更了 `real_name` 或 `class`，系统会检查数据库中是否存在同名同班级的**其他**学生，防止数据冲突。

**认证：** 需要（Bearer Token）

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 约束 | 说明 |
|------|------|------|------|------|
| `nickname` | string \| null | — | 1–50 字符，无控制字符 | 新昵称 |
| `real_name` | string \| null | — | 1–50 字符，无控制字符 | 新真实姓名 |
| `class` | string \| null | — | 1–50 字符，无控制字符 | 新班级 |

> 三个字段至少需要提供一个非 `null` 值。

**请求示例（仅修改昵称）：**

```json
{
  "nickname": "新昵称"
}
```

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
| `403 Forbidden` | 账号状态异常（如已被封禁） |
| `404 Not Found` | 用户不存在（通常不应出现） |
| `409 Conflict` | 修改后的真实姓名 + 班级与数据库中其他用户冲突 |
| `422 Unprocessable Entity` | 请求体字段格式错误（如包含控制字符、全部字段为 null） |
| `500 Internal Server Error` | 数据库更新失败 |

---

## 错误码一览

| HTTP 状态码 | 含义 | 常见场景 |
|-------------|------|---------|
| `200 OK` | 请求成功 | GET / PATCH 类接口 |
| `201 Created` | 资源创建成功 | POST /users/register |
| `400 Bad Request` | 请求参数或业务逻辑错误 | 问题表无效、答题未通过、旧密码错误 |
| `401 Unauthorized` | 认证失败 | Token 缺失、无效或过期 |
| `403 Forbidden` | 权限不足 | 账号被封禁 |
| `404 Not Found` | 资源不存在 | 用户不存在 |
| `409 Conflict` | 资源冲突 | 重复学生、修改后姓名班级冲突 |
| `422 Unprocessable Entity` | 请求体校验失败 | 字段类型/格式错误 |
| `429 Too Many Requests` | 频率限制 | IP 或姓名今日尝试次数过多、修改密码次数过多 |
| `503 Service Unavailable` | 服务暂时不可用 | Redis 断连、题库不足 |

---

## 注册模块 Redis Key 规范

| Key 格式 | 值类型 | 用途 | TTL |
|----------|--------|------|-----|
| `reg:qsheet:{sheet_id}` | JSON string | 问题表完整数据（含答案，仅服务端使用） | 24h |
| `reg:qsheet_atm:{sheet_id}` | integer | 该问题表的答题尝试次数 | 24h |
| `reg:ip_atm:{ip}:{YYYY-MM-DD}` | integer | IP 当日注册尝试次数 | 24h |
| `reg:name_atm:{name_hex}:{YYYY-MM-DD}` | integer | 同名用户当日注册尝试次数（`name_hex` 为 UTF-8 十六进制编码） | 24h |
| `reg:ip_sheets:{ip}:{YYYY-MM-DD}` | integer | IP 当日问题表获取次数 | 24h |
| `user:pwd_chg:{user_uuid}:{YYYY-MM-DD}` | integer | 用户当日修改密码尝试次数 | 24h |

> `name_hex` 是将 `real_name` 字符串以 UTF-8 编码后转为十六进制字符串，用于避免特殊字符污染 Redis key。

---

## 通用约定

| 项目 | 说明 |
|------|------|
| 数据格式 | 请求体与响应体均为 JSON |
| 字符编码 | UTF-8 |
| 认证方式 | Bearer Token（JWT，HS256，7 天有效期） |
| 时间格式 | ISO 8601（`YYYY-MM-DDTHH:MM:SSZ`） |
| 错误结构 | `{ "detail": "<错误描述>" }` |

---

## Auth — 认证

路由前缀：`/api/v1/auth`  
来源文件：`modules/api/v1/auth.py`

---

### POST /auth/login

**说明：** 使用用户名或邮箱 + 密码登录，返回 JWT access token。

**认证：** 不需要

**请求：** `application/x-www-form-urlencoded`（OAuth2 表单格式）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `username` | string | ✓ | 用户名或邮箱 |
| `password` | string | ✓ | 明文密码 |

**成功响应 `200 OK`：**

```json
{
  "access_token": "<JWT>",
  "token_type": "bearer"
}
```

**错误响应：**

| 状态码 | 场景 |
|--------|------|
| `401 Unauthorized` | 用户不存在或密码错误 |

---

### GET /auth/me

**说明：** 返回当前登录用户的基本信息。

**认证：** 需要（Bearer Token）

**成功响应 `200 OK`：**

```json
{
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "real_name": "张三",
  "role": "normal-user"
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

### 注册整体流程

```
客户端                              服务端
  │                                    │
  │── GET /users/register/questions ──▶│  随机抽 5 道题，存入 Redis
  │◀─ { sheet_id, questions[] } ───────│  返回题目（不含答案）
  │                                    │
  │── POST /users/register ───────────▶│  1. IP 今日尝试 ≤ 10
  │   { nickname, real_name,           │  2. real_name 今日尝试 ≤ 3
  │     classtype, class,              │  3. sheet 存在且尝试 ≤ 3
  │     sheet_id, answers[] }          │  4. 答对 ≥ 3 道
  │                                    │  5. 无重复学生（姓名+班级）
  │◀─ { access_token, user{} } ────────│  写入 DB，返回 JWT
```

---

### GET /users/register/questions

**说明：** 从 `register_questions` 表中随机抽取 5 道 `active` 状态的题目，生成一张问题表存入 Redis（TTL 24 小时），返回给客户端的数据**不含答案**。

每个 IP 每天最多获取 **4 张**问题表（允许换题最多 3 次）。

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
| `503 Service Unavailable` | 题库中 active 题目不足 5 道，或 Redis 不可用 |

---

### POST /users/register

**说明：** 提交注册请求，携带个人信息、问题表 ID 和答案列表。

**认证：** 不需要

**请求体 `application/json`：**

| 字段 | 类型 | 必填 | 约束 | 说明 |
|------|------|------|------|------|
| `nickname` | string | ✓ | 1–50 字符，无控制字符 | 昵称 |
| `real_name` | string | ✓ | 1–50 字符，无控制字符 | 真实姓名 |
| `classtype` | string | ✓ | `"high-school"` 或 `"university"` | 学段 |
| `class` | string | ✓ | 1–50 字符，无控制字符 | 班级 |
| `sheet_id` | string | ✓ | 来自 GET /users/register/questions | 问题表 ID |
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
4. 5 道题中至少 **3 道**答对（大小写不敏感，去除首尾空白）
5. 数据库中不存在相同 `real_name + class` 的学生

> **注意：** 步骤 1–3 的计数器在校验答案**之前**递增，防止暴力枚举。注册成功后问题表从 Redis 删除，不可重复使用。

**成功响应 `201 Created`：**

```json
{
  "access_token": "<JWT>",
  "token_type": "bearer",
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

**写入数据库的默认值：**

| 字段 | 默认值 |
|------|--------|
| `user_role` | `"normal-user"` |
| `is_verified` | `false` |
| `current_status` | `"normal"` |
| 其他字段（`password`、`email` 等） | `null` |

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
| `503 Service Unavailable` | Redis 不可用 |

---

## 错误码一览

| HTTP 状态码 | 含义 | 常见场景 |
|-------------|------|---------|
| `200 OK` | 请求成功 | GET 类接口 |
| `201 Created` | 资源创建成功 | POST /users/register |
| `400 Bad Request` | 请求参数或业务逻辑错误 | 问题表无效、答题未通过 |
| `401 Unauthorized` | 认证失败 | Token 缺失、无效或过期 |
| `409 Conflict` | 资源冲突 | 重复学生 |
| `422 Unprocessable Entity` | 请求体校验失败 | 字段类型/格式错误 |
| `429 Too Many Requests` | 频率限制 | IP 或姓名今日尝试次数过多 |
| `503 Service Unavailable` | 服务暂时不可用 | Redis 断连、题库不足 |

---

## 注册模块 Redis Key 规范

| Key 格式 | 值类型 | 用途 | TTL |
|----------|--------|------|-----|
| `reg:qsheet:{sheet_id}` | JSON string | 问题表完整数据（含答案，仅服务端使用） | 24h |
| `reg:qsheet_atm:{sheet_id}` | integer | 该问题表的答题尝试次数 | 24h |
| `reg:ip_atm:{ip}:{YYYY-MM-DD}` | integer | IP 当日注册尝试次数 | 24h |
| `reg:name_atm:{name_hex}:{YYYY-MM-DD}` | integer | 同名用户当日注册尝试次数（`name_hex` 为 UTF-8 十六进制编码） | 24h |
| `reg:ip_sheets:{ip}:{YYYY-MM-DD}` | integer | IP 当日问题表获取次数 | 24h |

> `name_hex` 是将 `real_name` 字符串以 UTF-8 编码后转为十六进制字符串，用于避免特殊字符污染 Redis key。
