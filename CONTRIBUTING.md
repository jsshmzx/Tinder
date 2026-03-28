# Contributing to Tinder

感谢你为 Tinder 项目做出贡献。

本文档说明了如何在本地开发、提交代码并发起 Pull Request。请在提交前完整阅读。

## 1. 开发环境

- Python 3.10+
- PostgreSQL
- Redis

建议使用虚拟环境：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

配置环境变量：

```bash
cp .env.example .env
```

然后按需修改 `.env` 中的连接信息。

## 2. 本地运行

先执行数据库迁移：

```bash
python db_migrate.py
```

再启动服务：

```bash
python server.py
```

默认监听端口：`1912`。

## 3. 分支与提交

- 从 `main` 拉取最新代码后创建功能分支。
- 一个 Pull Request 只解决一个明确问题。
- 提交信息请清晰描述“做了什么”和“为什么做”。

推荐分支命名：

- `feat/<short-description>`
- `fix/<short-description>`
- `refactor/<short-description>`
- `docs/<short-description>`

## 4. 代码规范

- 使用 Python 3.10+ 语法。
- 新增或修改函数时尽量补充类型注解。
- 导入分组顺序：标准库 -> 第三方 -> 本地模块（`core`、`modules`）。
- 不要使用 `print()` 进行业务日志输出，请使用 `custom_log(level, message)`。

## 5. 数据库与迁移规范

- ORM 使用 SQLAlchemy 2.x 异步模式。
- 会话通过 `async with get_session() as session:` 使用。
- 新表或变更 SQL 放在 `core/database/migrations/SQL/`。
- 文件命名：
  - 新表：`initial_<tablename>.sql`
  - 变更：`alter_<tablename>_<description>.sql`
- SQL 中优先使用：
  - `CREATE TABLE IF NOT EXISTS`
  - `CREATE INDEX IF NOT EXISTS`

## 6. 测试要求

提交前至少运行：

```bash
pytest tests/unit/ --tb=short
```

如果改动涉及数据库、Redis、中间件或 API 行为，请同时运行：

```bash
pytest tests/integration/ --tb=short
```

完整测试：

```bash
pytest
```

## 7. Pull Request 清单

发起 PR 前请确认：

- 代码已与 `main` 同步。
- 相关测试已通过。
- 如果有接口/行为变化，已在 PR 描述中说明。
- 如果有数据库变更，已包含对应迁移文件。
- 文档（如 README、接口说明）已按需更新。

推荐 PR 描述包含：

- 变更背景
- 主要改动
- 测试结果
- 潜在影响与回滚方式（如适用）

## 8. Issue 与安全问题

- 普通缺陷和需求，请使用 GitHub Issue 模板。
- 安全问题请不要公开披露，参考 `SECURITY.md` 进行报告。

再次感谢你的贡献。