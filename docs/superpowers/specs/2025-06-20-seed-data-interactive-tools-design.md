# 交互式测试数据生成工具 — 设计文档

## 背景

现有 `tools/generate_test_user_data.py` 是一个 836 行的单体文件，通过 argparse 参数控制 14 张表的数据生成。使用体验不够友好，且单体文件难以维护。

## 目标

1. 按表拆分为独立模块，每个模块职责单一
2. 改用交互式问答设计，提供引导式使用体验
3. 完全替换旧文件

## 目录结构

```
tools/
├── seed_data.py              # 统一入口，交互式引导
└── seed_data/                # 各表生成器模块包
    ├── __init__.py           # 注册所有生成器
    ├── base.py               # 共享工具函数
    ├── users.py              # 用户
    ├── songs.py              # 歌曲
    ├── wall_sayings.py       # 说说
    ├── comments.py           # 评论
    ├── tags.py               # 标签
    ├── tasks.py              # 任务
    ├── stores_and_restaurants.py  # 商铺/餐馆
    ├── song_arrangements.py  # 歌单安排
    ├── register_questions.py # 注册问题
    ├── tokens.py             # API 令牌
    ├── vote.py               # 投票
    ├── favourites.py         # 收藏
    ├── wall_looking_for.py   # 寻物/寻人
    └── relations.py          # 关联关系
```

## 模块职责

### `base.py` — 共享基础

- Faker 实例（zh_CN）
- DB session 管理（`get_session()` 导入）
- 密码工具函数（`_double_sha256`, `get_password_hash`）
- `_choice()`, `_maybe()` 等随机辅助函数
- 全局 `USER_UUIDS: list[str]` 列表（内存传递，仅当前进程有效）
- `get_user_count()` 查询已有用户数量

### `seed_data.py` — 统一入口

- 显示编号菜单，多选表（逗号分隔）
- 识别依赖关系（非用户表依赖用户表）
- 按序执行选中的表生成器
- 每轮完成后询问是否继续
- 支持 `--quick` 参数跳过交互全部默认值
- 支持 `--only TABLES` 参数直接指定表名（无交互）

### 各 `table.py` — 单个表生成器

每个模块暴露一个 async 函数：

```python
async def generate(session: AsyncSession, interactive: bool = True) -> None:
    """生成[表名]测试数据。interactive=True 时通过 input() 交互输入参数。"""
```

交互式流程：
1. 提示输入数量（提供默认值）
2. 提示输入关键字段选项
3. 显示生成摘要，询问是否确认
4. 生成并写入 DB
5. 打印结果

`interactive=False` 时全部使用合理默认值（供 `--quick` 使用）。

## 交互流程

```
$ python tools/seed_data.py

============================================================
  Tinder 测试数据生成器
============================================================
要生成哪些表的数据？（可多选，逗号分隔，如 1,3,5）
  1) 用户
  2) 歌曲
  3) 说说
  4) 评论
  5) 标签
  6) 任务
  7) 商铺/餐馆
  8) 歌单安排
  9) 注册问题
  10) API令牌
  11) 投票
  12) 收藏
  13) 寻物/寻人
  14) 关联关系
  15) 全部
  0) 退出
请输入编号: 1,2

--- 用户生成 ---
要生成多少个用户？[默认: 100]: 50
[生成中...]
✅ 成功插入 50 个用户

--- 歌曲生成 ---
要生成多少首歌曲？[默认: 50]: 30
[生成中...]
✅ 成功插入 30 首歌曲

还要继续生成其他表吗？(y/n) [n]:
```

## 依赖处理

- 所有非用户表依赖用户表的外键引用
- 每个表生成前检查 `USER_UUIDS` 是否为空，为空则打印提示并询问「需要先插入一些用户吗？」
- 如果已经在当前会话生成了用户，`USER_UUIDS` 列表已填充，直接使用
- 使用内存列表传递 UUID 引用，不写中间文件

## 错误处理

- 每个表生成独立 try/except，不会因一张表失败阻塞其他表
- 打印清晰错误信息
- DB 使用 `ON CONFLICT DO NOTHING` 防重复

## 数据完整性

- 沿用现有逻辑：所有表都保持合理的默认密码（password123）
- `ON CONFLICT (uuid) DO NOTHING` 防止重复插入
- 兼容现有 DB schema
