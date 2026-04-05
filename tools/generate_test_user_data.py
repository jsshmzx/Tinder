import asyncio
import uuid
import random
import sys
import os

# 添加项目根目录到 sys.path 使得 core 等模块可以被正常识别
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from faker import Faker
from sqlalchemy import text
from core.database.connection.pgsql import get_session
from core.security.hash import get_password_hash

# 加载环境变量
from dotenv import load_dotenv
load_dotenv()

fake = Faker('zh_CN')

async def generate_users(count: int = 1000):
    print(f"开始生成 {count} 个测试用户...")
    password_hash = get_password_hash("password123")
    
    users_to_insert = []

    for i in range(count):
        user_data = {
            "uuid": str(uuid.uuid4()),
            "avatar_url": fake.image_url(),
            "nickname": fake.user_name(),
            "real_name": fake.name(),
            "class_": f"高{random.randint(1, 3)}（{random.randint(1, 20)}）班",
            "class_type": random.choice(["本部", "副校"]),
            "current_status": random.choice(["在校", "毕业", "休学"]),
            "score": random.randint(0, 1000),
            "user_role": "user",
            "title": random.choice(["新手", "达人", "老司机", "无"]),
            "views": random.randint(0, 5000),
            "is_verified": random.choice([True, False]),
            "password": password_hash
        }
        users_to_insert.append(user_data)

    try:
        async with get_session() as session:
            query = text("""
                INSERT INTO users (
                    uuid, avatar_url, nickname, real_name, class, class_type, 
                    current_status, score, user_role, title, views, is_verified, password
                ) VALUES (
                    :uuid, :avatar_url, :nickname, :real_name, :class_, :class_type,
                    :current_status, :score, :user_role, :title, :views, :is_verified, :password
                )
            """)
            await session.execute(query, users_to_insert)
            await session.commit()
        print(f"成功通过直接原生 SQL 访问数据库的方式批量插入了 {count} 个用户。")
    except Exception as e:
        print(f"插入记录时遇到错误: {e}")

    print("测试用户生成完毕！(所有测试用用户的默认密码均为: password123)")

async def main():
    # 后续还能在此函数中调用其他的测试数据生成器（例如文章、评论、日志等）
    await generate_users(1000)

if __name__ == "__main__":
    asyncio.run(main())
