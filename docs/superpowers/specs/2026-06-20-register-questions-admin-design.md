# 注册问题管理功能设计

## 概述

为管理员添加注册问题（register_questions）的 CRUD + 批量管理功能，包括后端 API 和前端管理页面。题目类型支持选择题、判断题、填空题，统一使用文本比对（trim+lowercase）进行答案校验。

## 题型存储格式

选择题的选项不再内嵌在 question 文本中，改为独立的 `options` 字段（JSON 文本）。

| 题型 | question_type | question 示例 | options | answer 示例 |
|------|---------------|--------------|---------|------------|
| 选择题 | choice | "以下哪个是中国首都？" | ["北京","上海","广州","深圳"] | "北京" |
| 判断题 | true_false | "地球是圆的" | null | "true" / "false" |
| 填空题 | fill_blank | "中国的首都是____" | null | "北京" |

答案校验方式（与现有注册流程一致）：`answer.trim().lowercase()` 精确字符串比对。

## 数据库变更

在现有 `register_questions` 表上新增一列：

```sql
ALTER TABLE register_questions
  ADD COLUMN IF NOT EXISTS options TEXT;
```

`options` 存储 JSON 数组字符串（如 `["北京","上海","广州"]`），非选择题为 `NULL`。

## 后端 API

所有接口需要 **superadmin** 角色（`MinRoleChecker(Role.SUPERADMIN.value)`），无需超级密码。

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/admin/questions` | 分页搜索，支持 keyword（模糊匹配 question）/ type / status 筛选 |
| `GET` | `/admin/questions/total` | 题目总数（同筛选参数） |
| `POST` | `/admin/questions` | 新建题目 |
| `PATCH` | `/admin/questions/{uuid}` | 编辑题目 |
| `DELETE` | `/admin/questions/{uuid}` | 单题删除 |
| `POST` | `/admin/questions/batch-delete` | 批量删除（body: `{ uuids: [...] }`） |
| `PATCH` | `/admin/questions/batch-status` | 批量切换状态（body: `{ uuids: [...], status: "active"/"inactive" }`） |
| `PATCH` | `/admin/questions/{uuid}/status` | 单题切换状态（body: `{ status: "active"/"inactive" }`） |

### 创建/编辑请求体

```json
{
  "question": "以下哪个是中国首都？",
  "question_type": "choice",
  "question_level": "easy",
  "answer": "北京",
  "options": ["北京", "上海", "广州", "深圳"]
}
```

- `question_type` 为 `"choice"` 时，`options` 必填且至少包含 2 个选项，`answer` 必须是选项之一。
- `question_type` 为 `"true_false"` 时，`answer` 仅允许 `"true"` 或 `"false"`。
- `question_type` 为 `"fill_blank"` 时，`options` 应为 `null`。
- 新建时自动生成 uuid，`created_by` 设为当前登录用户 uuid，`current_status` 默认为 `"active"`。

### DAO 层补充

在 `RegisterQuestionsDAO` 中新增方法，用于支持分页搜索、按条件计数、批量删除、批量状态更新。

## 前端页面

### 路由

`/register-questions`，菜单名"注册问题管理"。

### 页面结构

沿用用户管理页面的风格：`ProTable` + Ant Design。

**顶部统计卡片**（4 列）：
- 总题目数 / 选择题数 / 判断题数 / 填空题数

**表格列**：
| 列 | 说明 |
|------|------|
| ID | 自增 id |
| 题目 | question 文本，截断显示 |
| 类型 | Tag 标签（选择/判断/填空） |
| 等级 | easy / medium / hard |
| 状态 | Badge（active=绿色 / inactive=灰色） |
| 创建时间 | dateTime |
| 操作 | 详情 / 编辑 / 删除 |

**搜索栏**：关键词（question 模糊匹配）+ 题型下拉 + 状态下拉

**工具栏**：新建按钮

**批量操作栏**（选中行后出现）：批量删除 / 批量切换状态

### 新建/编辑弹窗

- 题目内容（TextArea，必填）
- 题目类型（Select：选择题/判断题/填空题，必填）
- 等级（Select：简单/中等/困难，可选）
- 选项列表（仅选择题显示，动态增删行）
- 正确答案（根据题型动态切换：选择题→下拉选选项；判断题→true/false 单选；填空题→文本输入框，必填）

### 详情 Drawer

展示题目全部字段，只读。

## 组件树

```
RegisterQuestions/
  index.tsx          — 主页面（ProTable + 统计 + 搜索 + 批量操作）
                        ├── 新建/编辑 Modal（动态表单）
                        ├── 批量状态切换 Modal
                        ├── 删除确认 Modal
                        └── 详情 Drawer
```

## 边界情况

- 选择题必须至少 2 个选项，答案必须在选项中。
- 不能删除或修改选项时导致已有答案不在选项中。
- 删除操作无需超级密码确认，单次弹窗确认即可。
- 批量状态切换若部分失败应返回成功数与失败数（类似 `batchUpdateUsers` 的模式）。
