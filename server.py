# 引入依赖
import uvicorn, os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from datetime import datetime
import platform
from typing import Dict, Any
from core.helper.ContainerCustomLog.index import custom_log
from core.middleware.firewall.index import FirewallMiddleware
from core.database.connection.redis import redis_conn
from core.database.connection.db import dispose_engine, get_session

# 加载环境变量
load_dotenv()
os.environ['TZ'] = 'Asia/Shanghai' # 设置时区为上海

# 生产环境禁用API文档
APP_ENV = os.getenv('APP_ENV', 'development').lower()
DOCS_URL = '/docs' if APP_ENV == 'development' else None
REDOC_URL = '/redoc' if APP_ENV == 'development' else None


# 应用生命周期管理：启动时连接数据库，停止时断开
@asynccontextmanager
async def lifespan(app: FastAPI):
    from sqlalchemy import text
    try:
        async with get_session() as session:
            await session.execute(text("SELECT 1"))
        custom_log("SUCCESS", "PostgreSQL 连接成功")
    except Exception as exc:
        custom_log("ERROR", f"PostgreSQL 连接失败: {exc}")
    redis_conn.start()
    yield
    await dispose_engine()
    custom_log("SUCCESS", "PostgreSQL 连接已关闭")
    redis_conn.stop()


# 创建FastAPI应用（生产环境禁用API文档）
app = FastAPI(lifespan=lifespan, docs_url=DOCS_URL, redoc_url=REDOC_URL)

# 配置CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# 注册防火墙中间件（在 CORS 之后，路由之前）
app.add_middleware(FirewallMiddleware)
# 导入模块
from modules.index.index import app as index_router
# 导入路由
app.include_router(index_router)


# 尝试启动服务器
custom_log("SUCCESS", "Tinder服务器启动中...")
custom_log("SUCCESS", f"===================================================")
custom_log("SUCCESS", f"Python版本: {platform.python_version()}")
custom_log("SUCCESS", f"当前APP_ENV: {os.getenv('APP_ENV', 'not set')}")
custom_log("SUCCESS", f"===================================================")

if __name__ == "__main__":
    try:
        # 根据环境变量设置日志级别
        log_level = "info" if APP_ENV == "development" else "warning"
        
        uvicorn.run(
            app="server:app",
            host='0.0.0.0',
            port=1912,
            reload=True,
            access_log=False,
            log_level=log_level
        )
    except Exception as e:
        custom_log("ERROR", f"Error starting server: {e}")