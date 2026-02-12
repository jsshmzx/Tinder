# 引入依赖
import uvicorn, os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from datetime import datetime
import platform
from typing import Dict, Any

# 加载环境变量
load_dotenv()
os.environ['TZ'] = 'Asia/Shanghai' # 设置时区为上海


# 创建FastAPI应用
app = FastAPI()

# 配置CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 获取系统信息
def get_system_info() -> Dict[str, Any]:
    """获取应用的系统信息"""
    return {
        "name": "Tinder",
        "system_time": datetime.now().isoformat(),
        "system_version": platform.platform()
    }

# 根路由
@app.get("/")
async def root():
    """返回应用的系统信息"""
    return get_system_info()

# 尝试启动服务器
if __name__ == "__main__":
    try:
        uvicorn.run(app="server:app", host='0.0.0.0', port=1912, reload=True)
    except Exception as e:
        print(f"Error starting server: {e}")