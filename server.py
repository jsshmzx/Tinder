# 引入依赖
import uvicorn, os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import platform

from core.config import settings
from core.helper.CustomLog.index import CustomLog
from core.middleware.firewall.index import FirewallMiddleware
from core.database.connection.redis import redis_conn
from core.database.connection.pgsql import dispose_engine, get_session

# 设置时区
os.environ['TZ'] = settings.TZ

# 生产环境禁用API文档
APP_ENV = settings.APP_ENV
DOCS_URL = '/docs' if APP_ENV == 'development' else None
REDOC_URL = '/redoc' if APP_ENV == 'development' else None


# 应用生命周期管理：启动时连接数据库，停止时断开
@asynccontextmanager
async def lifespan(app: FastAPI):
    from sqlalchemy import text
    try:
        async with get_session() as session:
            await session.execute(text("SELECT 1"))
        CustomLog("SUCCESS", "PostgreSQL 连接成功")
    except Exception as exc:
        CustomLog("ERROR", f"PostgreSQL 连接失败: {exc}")
    redis_conn.start()

    # 启动定时任务调度器
    from core.cron.scheduler import start as start_scheduler, stop as stop_scheduler
    start_scheduler()

    yield

    # 停止定时任务调度器
    stop_scheduler()
    await dispose_engine()
    CustomLog("SUCCESS", "PostgreSQL 连接已关闭")
    redis_conn.stop()


# 创建FastAPI应用（生产环境禁用API文档）
app = FastAPI(lifespan=lifespan, docs_url=DOCS_URL, redoc_url=REDOC_URL)

# 配置CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)
# 注册防火墙中间件（在 CORS 之后，路由之前）
if settings.FW_ENABLED:
    app.add_middleware(FirewallMiddleware)
    CustomLog("INFO", "防火墙已启用（FW_ENABLED=true）")
# 导入模块
from modules.index.index import app as index_router
from modules.api.v1.router import router as api_v1_router
# 导入路由
app.include_router(index_router)
app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

# 尝试启动服务器
CustomLog("SUCCESS", "Tinder服务器启动中...")
CustomLog("SUCCESS", f"===================================================")
CustomLog("SUCCESS", f"Python版本: {platform.python_version()}")
CustomLog("SUCCESS", f"当前APP_ENV: {settings.APP_ENV}")
CustomLog("SUCCESS", f"===================================================")

if __name__ == "__main__":
    try:
        # 根据环境变量设置日志级别
        log_level = "info" if APP_ENV == "development" else "warning"

        uvicorn.run(
            app="server:app",
            host=settings.SERVER_HOST,
            port=settings.SERVER_PORT,
            reload=settings.SERVER_RELOAD,
            access_log=False,
            log_level=log_level
        )
    except Exception as e:
        CustomLog("ERROR", f"Error starting server: {e}")
