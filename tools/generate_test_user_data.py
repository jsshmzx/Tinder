#!/usr/bin/env python3
"""
测试数据生成器 — 一次性生成多表测试数据。

用法:
  python tools/generate_test_user_data.py                    # 默认：创建1000个用户（含搜索可用的 username/email）
  python tools/generate_test_user_data.py --all               # 所有表都生成（推荐）
  python tools/generate_test_user_data.py --users 50          # 仅50个用户
  python tools/generate_test_user_data.py --songs 200         # 仅200首歌
  python tools/generate_test_user_data.py --sayings 300       # 仅300条说说
  python tools/generate_test_user_data.py --comments 500      # 仅500条评论
  python tools/generate_test_user_data.py --tags 20           # 仅20个标签
  python tools/generate_test_user_data.py --tasks 50          # 仅50个任务
  python tools/generate_test_user_data.py --stores 30         # 仅30个商铺
  python tools/generate_test_user_data.py --arrangements 10   # 仅10个歌单安排
  python tools/generate_test_user_data.py --questions 15      # 仅15个注册问题
  python tools/generate_test_user_data.py --tokens 20         # 仅20个API令牌
  python tools/generate_test_user_data.py --all --count 500   # 全部表，每表500条
"""

import argparse
import asyncio
import hashlib
import random
import uuid
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from faker import Faker
from sqlalchemy import text
from core.database.connection.pgsql import get_session
from core.security.hash import get_password_hash
from dotenv import load_dotenv

load_dotenv()

fake = Faker('zh_CN')
USER_UUIDS: list[str] = []  # 记录已插入的用户 uuid，供外键引用


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _double_sha256(plain: str) -> str:
    """计算 SHA256(SHA256(plain)) 的 64 字符 hex 值。

    本系统的密码策略：客户端自行做双重哈希后传 hex 给服务端，
    服务端直接存储。所以 get_password_hash() 只做原样传递。
    但为了确保数据库存的是正确的"双重哈希双倍"，我们在这里手动算好，
    再把结果传给 get_password_hash（它原样返回）。
    """
    once = hashlib.sha256(plain.encode()).hexdigest()
    twice = hashlib.sha256(once.encode()).hexdigest()
    return twice


def _choice(*options):
    return random.choice(options)


def _maybe(none_rate=0.15):
    """有 none_rate 概率返回 None，用于模拟可空字段。"""
    return random.random() > none_rate


# ---------------------------------------------------------------------------
# 各表生成器
# ---------------------------------------------------------------------------

async def generate_users(count: int = 100):
    """生成测试用户，用户名格式 test_user_001 以便搜索。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 个测试用户...")
    print(f"{'='*60}")

    # 关键修正：这里先算好双重哈希值，再传给原样返回的 get_password_hash
    password_double_hashed = _double_sha256("password123")
    password_stored = get_password_hash(password_double_hashed)

    users_to_insert = []
    for i in range(count):
        nickname = fake.user_name()
        username = f"test_user_{i+1:04d}"
        email = f"{username}@test.com"
        uuid_val = str(uuid.uuid4())
        user_data = {
            "uuid": uuid_val,
            "username": username,
            "email": email,
            "avatar_url": fake.image_url(),
            "nickname": nickname,
            "real_name": fake.name(),
            "class_": f"高{random.randint(1, 3)}（{random.randint(1, 20)}）班",
            "class_type": _choice("本部", "副校"),
            "current_status": _choice("normal", "normal", "normal", "disabled", "banned"),
            "score": random.randint(0, 1000),
            "user_role": _choice("normal-user", "normal-user", "normal-user", "songlist_editor", "superadmin"),
            "title": _choice("新手", "达人", "老司机", "无"),
            "views": random.randint(0, 5000),
            "is_verified": _choice(True, False),
            "password": password_stored,
            "invited_by": None if random.random() > 0.3 else fake.user_name(),
        }
        users_to_insert.append(user_data)

    try:
        # 构造 SQL 参数列表（先映射 class_ → class）
        sql_params = []
        for d in users_to_insert:
            sql_params.append({
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
            })

        async with get_session() as session:
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

        USER_UUIDS.extend([u["uuid"] for u in users_to_insert])
        print(f"✅ 成功插入 {count} 个用户")
        print(f"   默认登录密码: password123")
        print(f"   示例: username=test_user_0001, password=password123")
    except Exception as e:
        print(f"❌ 插入用户失败: {e}")


async def generate_songs(count: int = 100):
    """生成测试歌曲。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 首测试歌曲...")
    print(f"{'='*60}")

    song_names = [
        "晴天", "七里香", "夜曲", "告白气球", "稻香", "青花瓷", "兰亭序",
        "一路向北", "演员", "丑八怪", "孤勇者", "光年之外", "起风了",
        "红色高跟鞋", "小幸运", "追光者", "大鱼", "凉凉", "消愁", "成都",
        "平凡之路", "南山南", "春风十里", "理想三旬", "往后余生",
    ]
    singers = [
        "周杰伦", "薛之谦", "陈奕迅", "邓紫棋", "林俊杰", "王菲",
        "毛不易", "赵雷", "朴树", "李荣浩", "张靓颖", "蔡徐坤",
        "周深", "张韶涵", "田馥甄", "刘瑞琦",
    ]
    platforms = ["网易云音乐", "QQ音乐", "酷狗音乐", "Apple Music", "Spotify"]

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "name": random.choice(song_names),
            "singer": random.choice(singers),
            "platform": random.choice(platforms),
            "status": _choice("active", "active", "inactive", "archived"),
            "vote": random.randint(0, 999),
            "recommend_by": random.choice(USER_UUIDS + [None] * 3) if USER_UUIDS else None,
            "recommend_words": fake.sentence(nb_words=6) if _maybe(0.4) else None,
            "reason": fake.sentence(nb_words=10) if _maybe(0.5) else None,
        })

    try:
        async with get_session() as session:
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


async def generate_sayings(count: int = 100):
    """生成测试说说（墙说）。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 条说说...")
    print(f"{'='*60}")

    if not USER_UUIDS:
        print("⚠️  没有用户数据，跳过说说生成")
        return

    template_contents = [
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
    song_names = ["晴天", "七里香", "孤勇者", "起风了", "成都"]

    values = []
    for _ in range(count):
        content = random.choice(template_contents).format(
            song=random.choice(song_names)
        )
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
        async with get_session() as session:
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


async def generate_comments(count: int = 100):
    """生成测试评论。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 条评论...")
    print(f"{'='*60}")

    if not USER_UUIDS:
        print("⚠️  没有用户数据，跳过评论生成")
        return

    comment_templates = [
        "说得好！", "赞一个", "同意楼上", "厉害厉害",
        "学到了，谢谢分享", "这个观点我不同意", "哈哈哈笑死",
        "路过看看", "收藏了", "顶一下", "好文！",
        "加油！", "辛苦了", "写的真棒", "期待更多内容",
    ]
    places = ["wall_sayings", "songs", "comments"]

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "status": _choice("active", "active", "hidden", "deleted"),
            "comment_place": random.choice(places),
            "author": random.choice(USER_UUIDS),
            "content": random.choice(comment_templates),
            "ip_address": fake.ipv4(),
            "user_agent": (
                _choice(
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
                    "Mozilla/5.0 (Linux; Android 13)",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                )
            ),
            "location": _choice("北京", "上海", "广州", "深圳", "杭州", "成都", None),
        })

    try:
        async with get_session() as session:
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


async def generate_tags(count: int = 20):
    """生成测试标签。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 个标签...")
    print(f"{'='*60}")

    tag_names = [
        "热门", "推荐", "最新", "校园", "生活", "学习", "美食",
        "旅行", "音乐", "电影", "读书", "运动", "游戏", "科技",
        "动漫", "摄影", "情感", "搞笑", "励志", "冷知识",
        "校园活动", "社团", "考研", "就业", "留学",
    ]

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "tag_name": random.choice(tag_names),
            "created_by": random.choice(USER_UUIDS + [None] * 2) if USER_UUIDS else None,
            "current_status": _choice("active", "active", "inactive"),
        })

    try:
        async with get_session() as session:
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


async def generate_tasks(count: int = 50):
    """生成测试任务。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 个任务...")
    print(f"{'='*60}")

    if not USER_UUIDS:
        print("⚠️  没有用户数据，跳过任务生成")
        return

    parts_list = [
        "前端", "后端", "数据库", "UI设计", "测试",
        "文案", "运营", "项目管理", "数据分析",
    ]

    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "content": fake.sentence(nb_words=12),
            "parts": random.choice(parts_list),
            "assigner": random.choice(USER_UUIDS),
            "status": _choice("todo", "in_progress", "done", "cancelled", "archived"),
        })

    try:
        async with get_session() as session:
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


async def generate_stores(count: int = 30):
    """生成测试商铺/餐馆。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 间商铺...")
    print(f"{'='*60}")

    prefixes = ["老王", "小李", "阿明", "大壮", "小美", "阿强", "刘叔", "陈姐", "张哥", "胖哥"]
    types = ["烧烤", "奶茶", "麻辣烫", "炸鸡", "火锅", "面馆", "甜品", "咖啡", "煎饼", "寿司"]

    locations = ["食堂三楼", "商业街A区", "北门对面", "南门右侧", "东区宿舍楼下", "教学楼B栋旁"]

    values = []
    for _ in range(count):
        name = f"{random.choice(prefixes)}{random.choice(types)}"
        days_offset = random.randint(-365, 0)
        values.append({
            "uuid": str(uuid.uuid4()),
            "name": name,
            "location": random.choice(locations),
            "likes": random.randint(0, 999),
            "ratings": round(random.uniform(1.0, 5.0), 2),
            "status": _choice("open", "open", "open", "closed", "renovating"),
        })

    try:
        async with get_session() as session:
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


async def generate_arrangements(count: int = 10):
    """生成测试歌单安排。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 个歌单安排...")
    print(f"{'='*60}")

    if not USER_UUIDS:
        print("⚠️  没有用户数据，跳过歌单安排生成")
        return

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
        async with get_session() as session:
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


async def generate_questions(count: int = 15):
    """生成测试注册问题。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 个注册问题...")
    print(f"{'='*60}")

    qa_pairs = [
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

    values = []
    for i in range(count):
        if i < len(qa_pairs):
            q, a = qa_pairs[i]
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
        })

    try:
        async with get_session() as session:
            await session.execute(
                text("""
                    INSERT INTO register_questions
                        (uuid, question, answer, created_by, question_level,
                         question_type, current_status)
                    VALUES
                        (:uuid, :question, :answer, :created_by, :question_level,
                         :question_type, :current_status)
                    ON CONFLICT (uuid) DO NOTHING
                """),
                values,
            )
            await session.commit()
        print(f"✅ 成功插入 {count} 个注册问题")
    except Exception as e:
        print(f"❌ 插入注册问题失败: {e}")


async def generate_tokens(count: int = 20):
    """生成测试API令牌。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 个API令牌...")
    print(f"{'='*60}")

    if not USER_UUIDS:
        print("⚠️  没有用户数据，跳过令牌生成")
        return

    permissions = ["read", "write", "admin", "read:users", "write:users", "read:songs", "write:songs"]

    values = []
    for _ in range(count):
        expired = random.random() > 0.3
        values.append({
            "uuid": str(uuid.uuid4()),
            "belong_to": random.choice(USER_UUIDS),
            "permission": random.choice(permissions),
            "assigner": random.choice(USER_UUIDS + [None] * 2),
            "current_status": _choice("active", "active", "expired", "revoked"),
        })

    try:
        async with get_session() as session:
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


async def generate_votes(count: int = 100):
    """生成测试投票记录。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 条投票记录...")
    print(f"{'='*60}")

    if not USER_UUIDS:
        print("⚠️  没有用户数据，跳过投票生成")
        return

    vote_types = ["song", "comment", "saying", "store"]
    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "vote_type": random.choice(vote_types),
            "committed_by": random.choice(USER_UUIDS),
            "content": str(random.randint(1, 1000)),
        })

    try:
        async with get_session() as session:
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


async def generate_favourites(count: int = 100):
    """生成测试收藏记录。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 条收藏记录...")
    print(f"{'='*60}")

    if not USER_UUIDS:
        print("⚠️  没有用户数据，跳过收藏生成")
        return

    types = ["song", "saying", "store", "comment"]
    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "user_uuid": random.choice(USER_UUIDS),
            "types": random.choice(types),
        })

    try:
        async with get_session() as session:
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

async def generate_looking_for(count: int = 30):
    """生成测试寻物启事。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 条寻物/寻人...")
    print(f"{'='*60}")

    if not USER_UUIDS:
        print("⚠️  没有用户数据，跳过寻物寻人生成")
        return

    types = ["lost_item", "found_item", "looking_for_person"]
    clues_list = [
        "黑色钱包，内有身份证和学生证",
        "白色AirPods，带蓝色硅胶套",
        "蓝色水杯，贴有姓名标签",
        "黑色笔记本，封面有涂鸦",
        "红色雨伞，折叠款",
    ]
    values = []
    for _ in range(count):
        values.append({
            "uuid": str(uuid.uuid4()),
            "current_status": _choice("active", "active", "resolved", "expired"),
            "real_status": _choice("pending", "confirmed", "rejected"),
            "seeker": random.choice(USER_UUIDS),
            "looking_for_type": random.choice(types),
            "helper": random.choice(USER_UUIDS + [None] * 3),
            "clues": random.choice(clues_list),
        })

    try:
        async with get_session() as session:
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

async def generate_relations(count: int = 100):
    """生成测试关联关系。"""
    print(f"\n{'='*60}")
    print(f"开始生成 {count} 条关联关系...")
    print(f"{'='*60}")

    types = ["tag_song", "tag_saying", "tag_user", "user_song"]
    values = []
    for _ in range(count):
        values.append({
            "tags_uuid": str(uuid.uuid4()),
            "related_uuid": str(uuid.uuid4()),
            "relation_type": random.choice(types),
        })

    try:
        async with get_session() as session:
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


# ---------------------------------------------------------------------------
# 调度入口
# ---------------------------------------------------------------------------

async def main():
    parser = argparse.ArgumentParser(
        description="Tinder 测试数据生成器 — 支持多表批量填充",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  %(prog)s                        # 生成1000个用户
  %(prog)s --all                  # 所有表都生成（推荐）
  %(prog)s --users 50 --songs 200 # 50个用户 + 200首歌
  %(prog)s --all --count 500      # 全部表，每表500条
        """,
    )
    parser.add_argument("--all", action="store_true", help="生成所有表的测试数据")
    parser.add_argument("--count", type=int, default=100, help="各表的数据量（与--all配合使用，默认100）")
    parser.add_argument("--users", type=int, default=0, help="生成 N 个测试用户")
    parser.add_argument("--songs", type=int, default=0, help="生成 N 首歌曲")
    parser.add_argument("--sayings", type=int, default=0, help="生成 N 条说说")
    parser.add_argument("--comments", type=int, default=0, help="生成 N 条评论")
    parser.add_argument("--tags", type=int, default=0, help="生成 N 个标签")
    parser.add_argument("--tasks", type=int, default=0, help="生成 N 个任务")
    parser.add_argument("--stores", type=int, default=0, help="生成 N 间商铺")
    parser.add_argument("--arrangements", type=int, default=0, help="生成 N 个歌单安排")
    parser.add_argument("--questions", type=int, default=0, help="生成 N 个注册问题")
    parser.add_argument("--tokens", type=int, default=0, help="生成 N 个API令牌")
    parser.add_argument("--votes", type=int, default=0, help="生成 N 条投票记录")
    parser.add_argument("--favourites", type=int, default=0, help="生成 N 条收藏")
    parser.add_argument("--looking-for", type=int, default=0, help="生成 N 条寻物/寻人")
    parser.add_argument("--relations", type=int, default=0, help="生成 N 条关联关系")

    args = parser.parse_args()

    # 没有指定参数时默认 = 仅生成1000用户
    has_specific = any(getattr(args, f) for f in
                       ["users", "songs", "sayings", "comments", "tags", "tasks",
                        "stores", "arrangements", "questions", "tokens", "votes",
                        "favourites", "looking_for", "relations"])

    if not args.all and not has_specific:
        args.users = 1000

    # --all 模式 / 用户相关的表始终先生成用户
    need_users = (
        args.all
        or args.users > 0
        or (args.sayings > 0 or args.comments > 0)
        or (args.tasks > 0 or args.tokens > 0)
        or (args.votes > 0 or args.favourites > 0)
        or (args.looking_for > 0 or args.arrangements > 0)
    )

    default_count = args.count if args.all else 0

    print("=" * 60)
    print("  Tinder 测试数据生成器")
    print("=" * 60)

    # 1. 用户（始终最先，其他表需要 uuid）
    if args.users > 0 or (need_users and default_count > 0):
        await generate_users(args.users or default_count)

    # 如果只生成了用户就退出
    if not args.all and not any([
        args.songs, args.sayings, args.comments, args.tags, args.tasks,
        args.stores, args.arrangements, args.questions, args.tokens,
        args.votes, args.favourites, args.looking_for, args.relations,
    ]):
        print("\n✅ 数据生成完毕！")
        return

    # 2. 其他表（依赖用户的外键）
    generators = [
        ("songs", args.songs, generate_songs),
        ("sayings", args.sayings, generate_sayings),
        ("comments", args.comments, generate_comments),
        ("tags", args.tags, generate_tags),
        ("tasks", args.tasks, generate_tasks),
        ("stores", args.stores, generate_stores),
        ("arrangements", args.arrangements, generate_arrangements),
        ("questions", args.questions, generate_questions),
        ("tokens", args.tokens, generate_tokens),
        ("votes", args.votes, generate_votes),
        ("favourites", args.favourites, generate_favourites),
        ("looking_for", args.looking_for, generate_looking_for),
        ("relations", args.relations, generate_relations),
    ]

    for name, count, generator in generators:
        if count > 0 or (args.all and default_count > 0):
            await generator(count or default_count)

    print(f"\n{'='*60}")
    print("  全部数据生成完毕！")
    print(f"  （测试用户默认密码均为: password123）")
    print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())
