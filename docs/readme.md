# Tinder 项目文档

本目录汇总 Tinder 后端服务的所有开发文档。

---

## 目录结构

```
docs/
├── readme.md          # 本文件 — 文档总索引
├── api/
│   └── v1/
│       └── readme.md  # API v1 接口文档（端点、请求/响应结构、错误码）
└── database/
    ├── readme.md      # 数据库使用指南（连接管理、DAO 层、迁移规范）
    └── db-migration.excalidraw  # 数据库迁移流程图
```

---

## 快速导航

| 文档 | 内容 |
|------|------|
| [API v1 接口文档](api/v1/readme.md) | 所有 HTTP 端点的请求/响应格式、认证方式、错误码、注册流程图 |
| [数据库使用指南](database/readme.md) | PostgreSQL + Redis 连接管理、DAO 层 CRUD 用法、表结构一览、迁移规范 |

---

## 项目概览

- **框架：** FastAPI (Python 3.10+)
- **数据库：** PostgreSQL (asyncpg + SQLAlchemy 2.x 异步 ORM)
- **缓存：** Redis
- **端口：** 1912
- **测试：** pytest + pytest-asyncio + httpx

开发环境搭建与运行指南请参阅项目根目录的 [README.md](../README.md)。
