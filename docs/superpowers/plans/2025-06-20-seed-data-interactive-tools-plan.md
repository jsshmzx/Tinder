# 交互式测试数据生成工具 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the monolithic `generate_test_user_data.py` into interactive, modular per-table generators with a menu-driven entry point.

**Architecture:** A `tools/seed_data.py` entry point presents a numbered menu. Selecting a table dispatches to the corresponding module under `tools/seed_data/`. Each generator function is async, accepts a session and `interactive` flag, and guides the user through data generation via `input()` prompts. Shared utilities (DB session, faker, password hashing, random helpers, USER_UUIDS list) live in `base.py`.

**Tech Stack:** Python 3.14, asyncio, SQLAlchemy async, Faker (zh_CN), FastAPI project import

**Password note:** The current project uses SHA256 double-hash mode — `get_password_hash()` is a no-op that returns the input unchanged. `_double_sha256()` in the old code manually computes the two SHA256 rounds. This behavior is preserved.

---

## File Structure

```
tools/
├── seed_data.py              # NEW — interactive entry point (replaces generate_test_user_data.py)
└── seed_data/                # NEW — package of per-table modules
    ├── __init__.py
    ├── base.py               # shared: fake, _choice, _maybe, _double_sha256, get_password_hash, USER_UUIDS, session
    ├── users.py
    ├── songs.py
    ├── wall_sayings.py
    ├── comments.py
    ├── tags.py
    ├── tasks.py
    ├── stores_and_restaurants.py
    ├── song_arrangements.py
    ├── register_questions.py
    ├── tokens.py
    ├── vote.py
    ├── favourites.py
    ├── wall_looking_for.py
    └── relations.py
```

### Deleted

- `tools/generate_test_user_data.py` — removed after all functionality is ported

---

### Task 1: `base.py` — Shared utilities

**Files:**
- Create: `tools/seed_data/__init__.py`
- Create: `tools/seed_data/base.py`

**Interfaces:**
- Produces: `fake` (Faker instance), `_choice(*options)`, `_maybe(none_rate)`, `_double_sha256(plain)`, `get_password_hash(pwd)`, `USER_UUIDS: list[str]`, `get_session()`, `ensure_users_exist(session, interactive)` — shared by all generator modules

- [ ] **Step 1: Create `tools/seed_data/` package with `__init__.py`**

Write `tools/seed_data/__init__.py`:
```python
"""Seed data generation package — one module per table, called from tools/seed_data.py."""
```

- [ ] **Step 2: Write `tools/seed_data/base.py`**

```python
"""Shared utilities for seed data generators."""

import hashlib
import random
import sys
from typing import Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from faker import Faker
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from core.database.connection.pgsql import get_session as _get_db_session
from core.security.hash import get_password_hash

load_dotenv()

fake = Faker('zh_CN')

# Holds user UUIDs generated in the current session, for FK references
USER_UUIDS: list[str] = []


def _double_sha256(plain: str) -> str:
    """Compute SHA256(SHA256(plain)) → 64-char hex."""
    once = hashlib.sha256(plain.encode()).hexdigest()
    twice = hashlib.sha256(once.encode()).hexdigest()
    return twice


def _choice(*options: Any) -> Any:
    return random.choice(options)


def _maybe(none_rate: float = 0.15) -> bool:
    """Return True with probability (1 - none_rate)."""
    return random.random() > none_rate


def default_password() -> str:
    """Return the double-hashed default password for insertion."""
    return get_password_hash(_double_sha256("password123"))


def get_session():
    """Alias to core's get_session()."""
    return _get_db_session()


def _input_int(prompt: str, default: int) -> int:
    """Read an integer from stdin with a default value."""
    raw = input(prompt)
    if not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        print(f"  无效输入，使用默认值 {default}")
        return default


def _input_bool(prompt: str, default: bool = True) -> bool:
    """Read a y/n answer from stdin."""
    raw = input(prompt).strip().lower()
    if not raw:
        return default
    return raw in ('y', 'yes', '是')


async def ensure_users_exist(session: AsyncSession, interactive: bool) -> bool:
    """If USER_UUIDS is empty, ask the user whether to generate users first.

    Returns True if users are available afterward.
    """
    global USER_UUIDS
    if USER_UUIDS:
        return True

    if interactive:
        print("\n⚠️  当前没有用户数据，其他表的生成需要用户的外键引用。")
        if not _input_bool("是否先插入一些用户？(y/n) [y]: ", True):
            print("  已跳过用户生成，后续表将使用随机 UUID（可能违反外键约束）")
            return False

    from seed_data import users  # late import to avoid circular deps at module level
    await users.generate(session, interactive=interactive)
    return bool(USER_UUIDS)


async def load_existing_users(session: AsyncSession, limit: int = 500) -> None:
    """Load existing user UUIDs from DB into USER_UUIDS list."""
    global USER_UUIDS
    if USER_UUIDS:
        return
    result = await session.execute(text("SELECT uuid FROM users LIMIT :lim"), {"lim": limit})
    rows = result.fetchall()
    USER_UUIDS.extend(str(row[0]) for row in rows)
```

- [ ] **Step 3: Verify it imports cleanly**

Run: `cd /Users/huangtianrui/Documents/Project/jsshmzx/Tinder && python -c "from tools.seed_data.base import fake, _choice, default_password; print('OK')"`
Expected: `OK`

---

### Task 2: `users.py` generator

**Files:**
- Create: `tools/seed_data/users.py`

**Interfaces:**
- Produces: `generate(session, interactive=True) -> None`
  - Interactive prompts: count, password override, role distribution
  - Fills `USER_UUIDS` with inserted UUIDs
  - Uses `_input_int()` and `_input_bool()` from base

- [ ] **Step 1: Write `tools/seed_data/users.py`**

```python
"""Test user generator."""

import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _choice, _maybe, _input_int, _input_bool,
    default_password, _double_sha256,
)
from core.security.hash import get_password_hash


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    """Generate test users."""
    print(f"\n{'='*60}")
    print("  用户生成")
    print(f"{'='*60}")

    if interactive:
        count = _input_int("要生成多少个用户？[默认: 100]: ", 100)
        custom_pwd = _input_bool("使用默认密码 password123？(y/n) [y]: ", True)
        include_admin = _input_bool("是否包含一个 superadmin 账号？(y/n) [y]: ", True)
    else:
        count = 100
        custom_pwd = True
        include_admin = True

    if custom_pwd:
        password_stored = default_password()
    else:
        # Ask for custom password
        pwd = input("  请输入自定义密码: ").strip() or "password123"
        password_stored = get_password_hash(_double_sha256(pwd))

    users_to_insert = []
    start_idx = len(USER_UUIDS)  # offset to avoid reusing names

    # Optionally add a superadmin user
    if include_admin:
        admin_uuid = str(uuid.uuid4())
        users_to_insert.append({
            "uuid": admin_uuid,
            "username": "admin",
            "email": "admin@test.com",
            "avatar_url": fake.image_url(),
            "nickname": "管理员",
            "real_name": "系统管理员",
            "class_": "教职工",
            "class_type": "本部",
            "current_status": "normal",
            "score": 9999,
            "user_role": "superadmin",
            "title": "超级管理员",
            "views": 0,
            "is_verified": True,
            "password": password_stored,
            "invited_by": None,
        })

    for i in range(count):
        nickname = fake.user_name()
        username = f"test_user_{start_idx + i + 1:04d}"
        email = f"{username}@test.com"
        uuid_val = str(uuid.uuid4())
        users_to_insert.append({
            "uuid": uuid_val,
            "username": username,
            "email": email,
            "avatar_url": fake.image_url(),
            "nickname": nickname,
            "real_name": fake.name(),
            "class_": f"高{_choice(1, 2, 3)}（{_choice(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20)}）班",
            "class_type": _choice("本部", "副校"),
            "current_status": _choice("normal", "normal", "normal", "disabled", "banned"),
            "score": _choice(0, 0, 0, 100, 200, 500, 1000),
            "user_role": _choice("normal-user", "normal-user", "normal-user", "songlist_editor", "superadmin"),
            "title": _choice("新手", "达人", "老司机", None),
            "views": _choice(0, 10, 100, 1000, 5000),
            "is_verified": _choice(True, False),
            "password": password_stored,
            "invited_by": None if random.random() > 0.3 else fake.user_name(),
        })

    try:
        sql_params = [
            {
                "uuid": d["uuid"],
                "username": d["username"],
                "email": d["email"],
                "avatar_url": d["avatar_url"],
                "nickname": d["nickname"],
                "real_name": d["real_name"],
                "class_": d["class_"],
                "class_type": d["class_type"],
                "current_status": d["current_status"],
                "score": d["score"],
                "user_role": d["user_role"],
                "title": d["title"],
                "views": d["views"],
                "is_verified": d["is_verified"],
                "password": d["password"],
                "invited_by": d["invited_by"],
            }
            for d in users_to_insert
        ]

        await session.execute(
            text("""
                INSERT INTO users
                    (uuid, username, email, avatar_url, nickname, real_name, class,
                     class_type, current_status, score, user_role, title,
                     views, is_verified, password, invited_by)
                VALUES
                    (:uuid, :username, :email, :avatar_url, :nickname, :real_name, :class_,
                     :class_type, :current_status, :score, :user_role, :title,
                     :views, :is_verified, :password, :invited_by)
                ON CONFLICT (uuid) DO NOTHING
            """),
            sql_params,
        )
        await session.commit()

        new_uuids = [u["uuid"] for u in users_to_insert]
        USER_UUIDS.extend(new_uuids)
        admin_note = "（含 admin 账号）" if include_admin else ""
        print(f"✅ 成功插入 {len(users_to_insert)} 个用户 {admin_note}")
        print(f"   默认登录密码: {'password123' if custom_pwd else '(自定义)'}")
        if include_admin:
            print(f"   管理员: username=admin, password={'password123' if custom_pwd else '(自定义)'}")
        print(f"   示例: username=test_user_{start_idx + 1:04d}, password={'password123' if custom_pwd else '(自定义)'}")
    except Exception as e:
        print(f"❌ 插入用户失败: {e}")
        raise
```

- [ ] **Step 2: Write a quick smoke test**

```python
# Run with default settings (quick mode)
import asyncio
from tools.seed_data.base import get_session
from tools.seed_data.users import generate

async def test():
    async with get_session() as session:
        await generate(session, interactive=False)

asyncio.run(test())
```
But since we haven't built the entry point yet, just verify the import:

Run: `cd /Users/huangtianrui/Documents/Project/jsshmzx/Tinder && python -c "from tools.seed_data.users import generate; print('users.py OK')"`
Expected: `users.py OK`

---

### Task 3: `songs.py` generator

**Files:**
- Create: `tools/seed_data/songs.py`

**Interfaces:**
- Produces: `generate(session, interactive=True) -> None`
  - Interactive: count, picks random from song/singer lists
  - Reuses `USER_UUIDS` for `recommend_by` FK

- [ ] **Step 1: Write `tools/seed_data/songs.py`**

```python
"""Test songs generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _choice, _maybe, _input_int,
    get_session, ensure_users_exist,
)


SONG_NAMES = [
    "晴天", "七里香", "夜曲", "告白气球", "稻香", "青花瓷", "兰亭序",
    "一路向北", "演员", "丑八怪", "孤勇者", "光年之外", "起风了",
    "红色高跟鞋", "小幸运", "追光者", "大鱼", "凉凉", "消愁", "成都",
    "平凡之路", "南山南", "春风十里", "理想三旬", "往后余生",
]
SINGERS = [
    "周杰伦", "薛之谦", "陈奕迅", "邓紫棋", "林俊杰", "王菲",
    "毛不易", "赵雷", "朴树", "李荣浩", "张靓颖", "周深",
    "张韶涵", "田馥甄",
]
PLATFORMS = ["网易云音乐", "QQ音乐", "酷狗音乐", "Apple Music", "Spotify"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  歌曲生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            pass  # continue anyway
        count = _input_int("要生成多少首歌曲？[默认: 50]: ", 50)
    else:
        count = 50

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "name": random.choice(SONG_NAMES),
            "singer": random.choice(SINGERS),
            "platform": random.choice(PLATFORMS),
            "status": _choice("active", "active", "inactive", "archived"),
            "vote": random.randint(0, 999),
            "recommend_by": random.choice(USER_UUIDS) if USER_UUIDS and _maybe(0.6) else None,
            "recommend_words": fake.sentence(nb_words=6) if _maybe(0.4) else None,
            "reason": fake.sentence(nb_words=10) if _maybe(0.5) else None,
        })

    try:
        await session.execute(
            text("""
                INSERT INTO songs (uuid, name, singer, platform, status, vote,
                                   recommend_by, recommend_words, reason)
                VALUES (:uuid, :name, :singer, :platform, :status, :vote,
                        :recommend_by, :recommend_words, :reason)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 首歌曲")
    except Exception as e:
        print(f"❌ 插入歌曲失败: {e}")
```

---

### Task 4: `wall_sayings.py` generator

**Files:**
- Create: `tools/seed_data/wall_sayings.py`

**Interfaces:**
- Produces: `generate(session, interactive=True) -> None`
  - Requires USER_UUIDS; calls `ensure_users_exist()` if empty

- [ ] **Step 1: Write `tools/seed_data/wall_sayings.py`**

```python
"""Test wall_sayings generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _choice, _maybe, _input_int,
    ensure_users_exist,
)


TEMPLATES = [
    "今天天气真好，适合出去玩！",
    "新的一天，加油！",
    "分享一首好听的歌: {song}",
    "今天考试了，感觉还不错",
    "有没有人一起去吃饭？",
    "深夜emo时间...",
    "开心！今天遇到了好事",
    "推荐一部好看的电影",
    "大家周末有什么安排？",
    "早安，打工人！",
    "深夜放毒，刚吃了烧烤",
    "今天跑了个五公里，舒服",
    "这个学期的课好难啊",
    "想家了...",
    "终于放假了！开熏！",
]
SONGS = ["晴天", "七里香", "孤勇者", "起风了", "成都"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  说说生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过说说生成")
            return
        count = _input_int("要生成多少条说说？[默认: 50]: ", 50)
    else:
        if not USER_UUIDS:
            return
        count = 50

    values = []
    for _ in range(count):
        content = random.choice(TEMPLATES).format(song=random.choice(SONGS))
        values.append({
            "uuid": str(uuid.uuid4()),
            "author_uuid": random.choice(USER_UUIDS),
            "content": content,
            "saying_status": _choice("published", "published", "published", "draft", "deleted"),
            "saying_type": _choice("moment", "share", "qa", "confession"),
            "likes": random.randint(0, 999),
            "share_count": random.randint(0, 99),
            "views": random.randint(0, 9999),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO wall_sayings
                    (uuid, author_uuid, content, saying_status, saying_type,
                     likes, share_count, views)
                VALUES
                    (:uuid, :author_uuid, :content, :saying_status, :saying_type,
                     :likes, :share_count, :views)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条说说")
    except Exception as e:
        print(f"❌ 插入说说失败: {e}")
```

---

### Task 5: `comments.py` generator

**Files:**
- Create: `tools/seed_data/comments.py`

- [ ] **Step 1: Write `tools/seed_data/comments.py`**

```python
"""Test comments generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _choice, _maybe, _input_int,
    ensure_users_exist,
)


TEMPLATES = [
    "说得好！", "赞一个", "同意楼上", "厉害厉害",
    "学到了，谢谢分享", "这个观点我不同意", "哈哈哈笑死",
    "路过看看", "收藏了", "顶一下", "好文！",
    "加油！", "辛苦了", "写的真棒", "期待更多内容",
]
PLACES = ["wall_sayings", "songs", "comments"]
LOCATIONS = ["北京", "上海", "广州", "深圳", "杭州", "成都"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  评论生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过评论生成")
            return
        count = _input_int("要生成多少条评论？[默认: 50]: ", 50)
    else:
        if not USER_UUIDS:
            return
        count = 50

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "status": _choice("active", "active", "hidden", "deleted"),
            "comment_place": random.choice(PLACES),
            "author": random.choice(USER_UUIDS),
            "content": random.choice(TEMPLATES),
            "ip_address": fake.ipv4(),
            "user_agent": _choice(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
                "Mozilla/5.0 (Linux; Android 13)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            ),
            "location": _choice(random.choice(LOCATIONS), None),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO comments
                    (uuid, status, comment_place, author, content,
                     ip_address, user_agent, location)
                VALUES
                    (:uuid, :status, :comment_place, :author, :content,
                     :ip_address, :user_agent, :location)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条评论")
    except Exception as e:
        print(f"❌ 插入评论失败: {e}")
```

---

### Task 6: `tags.py`, `tasks.py`, `stores_and_restaurants.py`, `song_arrangements.py` generators

**Files:**
- Create: `tools/seed_data/tags.py`
- Create: `tools/seed_data/tasks.py`
- Create: `tools/seed_data/stores_and_restaurants.py`
- Create: `tools/seed_data/song_arrangements.py`

- [ ] **Step 1: Write `tools/seed_data/tags.py`**

```python
"""Test tags generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, _choice, _maybe, _input_int,
    ensure_users_exist,
)

TAG_NAMES = [
    "热门", "推荐", "最新", "校园", "生活", "学习", "美食",
    "旅行", "音乐", "电影", "读书", "运动", "游戏", "科技",
    "动漫", "摄影", "情感", "搞笑", "励志", "冷知识",
    "校园活动", "社团", "考研", "就业", "留学",
]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  标签生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            pass
        count = _input_int("要生成多少个标签？[默认: 20]: ", 20)
    else:
        count = 20

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "tag_name": random.choice(TAG_NAMES),
            "created_by": random.choice(USER_UUIDS) if USER_UUIDS and _maybe(0.6) else None,
            "current_status": _choice("active", "active", "inactive"),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO tags (uuid, tag_name, created_by, current_status)
                VALUES (:uuid, :tag_name, :created_by, :current_status)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 个标签")
    except Exception as e:
        print(f"❌ 插入标签失败: {e}")
```

- [ ] **Step 2: Write `tools/seed_data/tasks.py`**

```python
"""Test tasks generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _choice, _input_int,
    ensure_users_exist,
)

PARTS = ["前端", "后端", "数据库", "UI设计", "测试", "文案", "运营", "项目管理", "数据分析"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  任务生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过任务生成")
            return
        count = _input_int("要生成多少个任务？[默认: 30]: ", 30)
    else:
        if not USER_UUIDS:
            return
        count = 30

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "content": fake.sentence(nb_words=12),
            "parts": random.choice(PARTS),
            "assigner": random.choice(USER_UUIDS),
            "status": _choice("todo", "in_progress", "done", "cancelled", "archived"),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO tasks (uuid, content, parts, assigner, status)
                VALUES (:uuid, :content, :parts, :assigner, :status)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 个任务")
    except Exception as e:
        print(f"❌ 插入任务失败: {e}")
```

- [ ] **Step 3: Write `tools/seed_data/stores_and_restaurants.py`**

```python
"""Test stores_and_restaurants generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import _choice, _input_int

PREFIXES = ["老王", "小李", "阿明", "大壮", "小美", "阿强", "刘叔", "陈姐", "张哥", "胖哥"]
TYPES = ["烧烤", "奶茶", "麻辣烫", "炸鸡", "火锅", "面馆", "甜品", "咖啡", "煎饼", "寿司"]
LOCATIONS = ["食堂三楼", "商业街A区", "北门对面", "南门右侧", "东区宿舍楼下", "教学楼B栋旁"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  商铺/餐馆生成")
    print(f"{'='*60}")

    if interactive:
        count = _input_int("要生成多少间商铺？[默认: 20]: ", 20)
    else:
        count = 20

    values = []
    for _ in range(count):
        name = f"{random.choice(PREFIXES)}{random.choice(TYPES)}"
        values.append({
            "uuid": str(uuid.uuid4()),
            "name": name,
            "location": random.choice(LOCATIONS),
            "likes": random.randint(0, 999),
            "ratings": round(random.uniform(1.0, 5.0), 2),
            "status": _choice("open", "open", "open", "closed", "renovating"),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO stores_and_restaurants
                    (uuid, name, location, likes, ratings, status)
                VALUES
                    (:uuid, :name, :location, :likes, :ratings, :status)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 间商铺")
    except Exception as e:
        print(f"❌ 插入商铺失败: {e}")
```

- [ ] **Step 4: Write `tools/seed_data/song_arrangements.py`**

```python
"""Test song_arrangements generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _input_int,
    ensure_users_exist,
)


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  歌单安排生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过歌单安排生成")
            return
        count = _input_int("要生成多少个歌单安排？[默认: 10]: ", 10)
    else:
        if not USER_UUIDS:
            return
        count = 10

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "week_number": random.randint(1, 52),
            "content": fake.sentence(nb_words=8),
            "created_by": random.choice(USER_UUIDS),
            "likes": random.randint(0, 999),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO song_arrangements
                    (uuid, week_number, content, created_by, likes)
                VALUES
                    (:uuid, :week_number, :content, :created_by, :likes)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 个歌单安排")
    except Exception as e:
        print(f"❌ 插入歌单安排失败: {e}")
```

---

### Task 7: `register_questions.py`, `tokens.py` generators

**Files:**
- Create: `tools/seed_data/register_questions.py`
- Create: `tools/seed_data/tokens.py`

- [ ] **Step 1: Write `tools/seed_data/register_questions.py`**

Note: `register_questions` table has an `options` column (added via ALTER TABLE) — include it in the INSERT.

```python
"""Test register_questions generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, fake, _choice, _maybe, _input_int,
    ensure_users_exist,
)

QA_PAIRS = [
    ("你的小学名称是什么？", "第一小学"),
    ("你最喜欢的科目是什么？", "数学"),
    ("你的宠物名字是什么？", "旺财"),
    ("你最想去的地方是哪里？", "日本"),
    ("你最喜欢的歌手是谁？", "周杰伦"),
    ("你的生日是？", "2000-01-01"),
    ("你父亲的名字是？", "张三"),
    ("你母亲的名字是？", "李四"),
    ("你的座右铭是？", "天道酬勤"),
    ("你的幸运数字是？", "7"),
]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  注册问题生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            pass
        count = _input_int("要生成多少个注册问题？[默认: 15]: ", 15)
    else:
        count = 15

    values = []
    for i in range(count):
        if i < len(QA_PAIRS):
            q, a = QA_PAIRS[i]
        else:
            q, a = fake.sentence(nb_words=6), fake.word()
        values.append({
            "uuid": str(uuid.uuid4()),
            "question": q,
            "answer": a,
            "created_by": random.choice(USER_UUIDS) if USER_UUIDS else None,
            "question_level": _choice("low", "medium", "high"),
            "question_type": _choice("text", "choice", "date"),
            "current_status": _choice("active", "active", "inactive"),
            "options": None,
        })

    try:
        await session.execute(
            text("""
                INSERT INTO register_questions
                    (uuid, question, answer, created_by, question_level,
                     question_type, current_status, options)
                VALUES
                    (:uuid, :question, :answer, :created_by, :question_level,
                     :question_type, :current_status, :options)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 个注册问题")
    except Exception as e:
        print(f"❌ 插入注册问题失败: {e}")
```

- [ ] **Step 2: Write `tools/seed_data/tokens.py`**

```python
"""Test API tokens generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, _choice, _maybe, _input_int,
    ensure_users_exist,
)

PERMISSIONS = ["read", "write", "admin", "read:users", "write:users", "read:songs", "write:songs"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  API令牌生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过令牌生成")
            return
        count = _input_int("要生成多少个API令牌？[默认: 20]: ", 20)
    else:
        if not USER_UUIDS:
            return
        count = 20

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "belong_to": random.choice(USER_UUIDS),
            "permission": random.choice(PERMISSIONS),
            "assigner": random.choice(USER_UUIDS) if _maybe(0.6) else None,
            "current_status": _choice("active", "active", "expired", "revoked"),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO tokens
                    (uuid, belong_to, permission, assigner, current_status)
                VALUES
                    (:uuid, :belong_to, :permission, :assigner, :current_status)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 个API令牌")
    except Exception as e:
        print(f"❌ 插入令牌失败: {e}")
```

---

### Task 8: `vote.py`, `favourites.py`, `wall_looking_for.py`, `relations.py` generators

**Files:**
- Create: `tools/seed_data/vote.py`
- Create: `tools/seed_data/favourites.py`
- Create: `tools/seed_data/wall_looking_for.py`
- Create: `tools/seed_data/relations.py`

- [ ] **Step 1: Write `tools/seed_data/vote.py`**

```python
"""Test vote records generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, _input_int,
    ensure_users_exist,
)


VOTE_TYPES = ["song", "comment", "saying", "store"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  投票记录生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过投票生成")
            return
        count = _input_int("要生成多少条投票记录？[默认: 50]: ", 50)
    else:
        if not USER_UUIDS:
            return
        count = 50

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "vote_type": random.choice(VOTE_TYPES),
            "committed_by": random.choice(USER_UUIDS),
            "content": str(random.randint(1, 1000)),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO vote (uuid, vote_type, committed_by, content)
                VALUES (:uuid, :vote_type, :committed_by, :content)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条投票记录")
    except Exception as e:
        print(f"❌ 插入投票失败: {e}")
```

- [ ] **Step 2: Write `tools/seed_data/favourites.py`**

```python
"""Test favourites generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, _input_int,
    ensure_users_exist,
)

TYPES = ["song", "saying", "store", "comment"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  收藏记录生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过收藏生成")
            return
        count = _input_int("要生成多少条收藏记录？[默认: 50]: ", 50)
    else:
        if not USER_UUIDS:
            return
        count = 50

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "user_uuid": random.choice(USER_UUIDS),
            "types": random.choice(TYPES),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO favourites (uuid, user_uuid, types)
                VALUES (:uuid, :user_uuid, :types)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条收藏记录")
    except Exception as e:
        print(f"❌ 插入收藏失败: {e}")
```

- [ ] **Step 3: Write `tools/seed_data/wall_looking_for.py`**

```python
"""Test wall_looking_for (失物招领) generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import (
    USER_UUIDS, _choice, _input_int,
    ensure_users_exist,
)

TYPES = ["lost_item", "found_item", "looking_for_person"]
CLUES_LIST = [
    "黑色钱包，内有身份证和学生证",
    "白色AirPods，带蓝色硅胶套",
    "蓝色水杯，贴有姓名标签",
    "黑色笔记本，封面有涂鸦",
    "红色雨伞，折叠款",
]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  寻物/寻人生成")
    print(f"{'='*60}")

    if interactive:
        if not await ensure_users_exist(session, interactive):
            print("⚠️  没有用户数据，跳过寻物寻人生成")
            return
        count = _input_int("要生成多少条记录？[默认: 20]: ", 20)
    else:
        if not USER_UUIDS:
            return
        count = 20

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "current_status": _choice("active", "active", "resolved", "expired"),
            "real_status": _choice("pending", "confirmed", "rejected"),
            "seeker": random.choice(USER_UUIDS),
            "looking_for_type": random.choice(TYPES),
            "helper": random.choice(USER_UUIDS + [None] * 3) if _choice(True, False) else None,
            "clues": random.choice(CLUES_LIST),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO wall_looking_for
                    (uuid, current_status, real_status, seeker,
                     looking_for_type, helper, clues)
                VALUES
                    (:uuid, :current_status, :real_status, :seeker,
                     :looking_for_type, :helper, :clues)
                ON CONFLICT (uuid) DO NOTHING
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条寻物/寻人记录")
    except Exception as e:
        print(f"❌ 插入寻物/寻人失败: {e}")
```

- [ ] **Step 4: Write `tools/seed_data/relations.py`**

```python
"""Test relations generator."""

import random
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tools.seed_data.base import _input_int

TYPES = ["tag_song", "tag_saying", "tag_user", "user_song"]


async def generate(session: AsyncSession, interactive: bool = True) -> None:
    print(f"\n{'='*60}")
    print("  关联关系生成")
    print(f"{'='*60}")

    if interactive:
        count = _input_int("要生成多少条关联关系？[默认: 50]: ", 50)
    else:
        count = 50

    values = []
    for _ in range(count):
        values.append({
            "tags_uuid": str(uuid.uuid4()),
            "related_uuid": str(uuid.uuid4()),
            "relation_type": random.choice(TYPES),
        })

    try:
        await session.execute(
            text("""
                INSERT INTO relations (tags_uuid, related_uuid, relation_type)
                VALUES (:tags_uuid, :related_uuid, :relation_type)
            """),
            values,
        )
        await session.commit()
        print(f"✅ 成功插入 {count} 条关联关系")
    except Exception as e:
        print(f"❌ 插入关联关系失败: {e}")
```

---

### Task 9: `seed_data.py` — Interactive entry point

**Files:**
- Create: `tools/seed_data.py`
- Delete: `tools/generate_test_user_data.py`

**Interfaces:**
- Consumes: all `generate(session, interactive)` functions from each module
- Imports: every module via late import inside the dispatch router

- [ ] **Step 1: Write `tools/seed_data.py`**

```python
#!/usr/bin/env python3
"""
交互式测试数据生成器 — 引导式问答，支持多表选择。

用法:
  python tools/seed_data.py                  # 交互式菜单，多选表
  python tools/seed_data.py --quick           # 全部默认值，无交互
  python tools/seed_data.py --only users,songs  # 仅指定表，无交互
"""

import argparse
import asyncio
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from seed_data.base import get_session, USER_UUIDS, load_existing_users

# ── 表注册表 ──────────────────────────────────────────────────────
# (display_name, module_path, function_name, needs_users)
TABLES = [
    ("1",  "用户",         "users",               True),       # users is self-sufficient
    ("2",  "歌曲",         "songs",               True),
    ("3",  "说说",         "wall_sayings",        True),
    ("4",  "评论",         "comments",            True),
    ("5",  "标签",         "tags",                True),
    ("6",  "任务",         "tasks",               True),
    ("7",  "商铺/餐馆",    "stores_and_restaurants", False),
    ("8",  "歌单安排",     "song_arrangements",   True),
    ("9",  "注册问题",     "register_questions",  True),
    ("10", "API令牌",      "tokens",              True),
    ("11", "投票",         "vote",                True),
    ("12", "收藏",         "favourites",          True),
    ("13", "寻物/寻人",    "wall_looking_for",    True),
    ("14", "关联关系",     "relations",           False),
]

ALL_KEY = "15"


def print_menu():
    """打印编号菜单。"""
    print("\n" + "=" * 60)
    print("  Tinder 测试数据生成器")
    print("=" * 60)
    print("要生成哪些表的数据？（可多选，逗号分隔，如 1,3,5）")
    for key, name, *_ in TABLES:
        print(f"  {key:>2}) {name}")
    print(f"  {ALL_KEY}) 全部")
    print(f"   0) 退出")


def parse_selection(raw: str) -> list[str]:
    """解析用户输入的逗号分隔编号，返回模块名列表。"""
    raw = raw.strip().replace("，", ",")
    if raw == ALL_KEY:
        return [entry[2] for entry in TABLES]  # all modules

    selected = []
    for part in raw.split(","):
        part = part.strip()
        for key, name, module, _ in TABLES:
            if part == key:
                selected.append(module)
                break
    return selected


async def run_generator(module_name: str, session, interactive: bool) -> None:
    """动态导入并运行一个生成器模块。"""
    # Skip users generation if already have some (ask first)
    if module_name == "users" and USER_UUIDS and interactive:
        skip = input(f"\n当前已有 {len(USER_UUIDS)} 个用户 UUID 可用。跳过用户生成？(y/n) [y]: ").strip().lower()
        if skip in ("", "y", "yes"):
            return

    mod = __import__(f"seed_data.{module_name}", fromlist=["generate"])
    await mod.generate(session, interactive=interactive)


async def main():
    parser = argparse.ArgumentParser(description="Tinder 交互式测试数据生成器")
    parser.add_argument("--quick", action="store_true", help="跳过交互，全部使用默认值生成所有表")
    parser.add_argument("--only", type=str, help="仅生成指定表（逗号分隔），如: users,songs")
    args = parser.parse_args()

    # ── --quick 模式 ──────────────────────────────────────────────
    if args.quick:
        print("=" * 60)
        print("  Quick 模式 — 全部默认值")
        print("=" * 60)
        async with get_session() as session:
            # Ensure existing users are loaded
            await load_existing_users(session)
            for _, _, module_name, _ in TABLES:
                await run_generator(module_name, session, interactive=False)
        print(f"\n{'='*60}")
        print("  全部数据生成完毕！（默认密码: password123）")
        print(f"{'='*60}")
        return

    # ── --only 模式 ──────────────────────────────────────────────
    if args.only:
        names = [n.strip() for n in args.only.split(",")]
        print(f"选择生成: {', '.join(names)}")
        async with get_session() as session:
            await load_existing_users(session)
            for name in names:
                await run_generator(name, session, interactive=False)
        print(f"\n✅ 指定表数据生成完毕！（默认密码: password123）")
        return

    # ── 交互式模式 ────────────────────────────────────────────────
    async with get_session() as session:
        # Load existing users so they're available
        await load_existing_users(session)

        while True:
            print_menu()
            raw = input("请输入编号: ").strip()
            if raw == "0":
                print("已退出。")
                return

            selected = parse_selection(raw)
            if not selected:
                print("⚠️  请选择有效的编号")
                continue

            # Ensure users are generated first if needed
            needs_users = any(
                module == "users" for module in selected
            )
            if not needs_users and not USER_UUIDS:
                print("\n⚠️  注意：部分表依赖用户数据，建议先生成用户。")
                add_users = input("是否先添加用户？(y/n) [y]: ").strip().lower()
                if add_users in ("", "y", "yes"):
                    await run_generator("users", session, interactive=True)

            for module_name in selected:
                await run_generator(module_name, session, interactive=True)

            again = input("\n还要继续生成其他表吗？(y/n) [n]: ").strip().lower()
            if again not in ("y", "yes", "是"):
                break

        print(f"\n{'='*60}")
        print("  全部数据生成完毕！（默认密码: password123）")
        print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 2: Remove old file and verify symmetry**

```bash
rm /Users/huangtianrui/Documents/Project/jsshmzx/Tinder/tools/generate_test_user_data.py
```

- [ ] **Step 3: Test the new tool imports**

Run: `cd /Users/huangtianrui/Documents/Project/jsshmzx/Tinder && python -c "from tools.seed_data.base import fake; from tools.seed_data.users import generate; print('All imports OK')"`
Expected: `All imports OK`

- [ ] **Step 4: Quick syntax check by running with --quick**

Run: `cd /Users/huangtianrui/Documents/Project/jsshmzx/Tinder && python tools/seed_data.py --quick`
Expected: Runs through all generators with defaults, prints success/error messages. (This will actually hit the DB — so only run if a DB is available.)
If no DB available, at minimum verify it reaches the async runner without syntax errors by checking argparse parsing:
```bash
cd /Users/huangtianrui/Documents/Project/jsshmzx/Tinder && python tools/seed_data.py --help
```
Expected: prints argparse help.

---

### Task 10: Final cleanup and commit

- [ ] **Step 1: Remove __pycache__ artifacts**

```bash
cd /Users/huangtianrui/Documents/Project/jsshmzx/Tinder && rm -rf tools/seed_data/__pycache__
```

- [ ] **Step 2: Create a `tools/__init__.py` if needed**

If `tools/__init__.py` doesn't exist, create it empty for package consistency.

- [ ] **Step 3: Commit**

```bash
cd /Users/huangtianrui/Documents/Project/jsshmzx/Tinder && \
git add tools/ && \
git rm tools/generate_test_user_data.py && \
git add docs/superpowers/ && \
git commit -m "refactor(tools): split test data generator into interactive modular tools

- Create tools/seed_data.py as interactive entry point
- Create tools/seed_data/ package with 14 per-table generator modules
- Each generator uses interactive input() prompts with sensible defaults
- Support --quick (all defaults) and --only (skip menu) modes
- Remove monolithic generate_test_user_data.py"
```
