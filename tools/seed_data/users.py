"""Test user generator."""

import random
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
        pwd = input("  请输入自定义密码: ").strip() or "password123"
        password_stored = get_password_hash(_double_sha256(pwd))

    users_to_insert = []
    start_idx = len(USER_UUIDS)

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
