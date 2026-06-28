"""公共基础：密码哈希、JSON 输出、随机密码、事件循环管理。"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import sys
from typing import Any, Awaitable, TypeVar

_T = TypeVar("_T")


# ---------------------------------------------------------------------------
# 事件循环管理
#
# CLI 需要同步调用异步 DAO。早期实现用 ``asyncio.run()`` 逐次创建并关闭
# 事件循环，并在 ``finally`` 里释放引擎来避免连接池跨 loop 复用。但这会
# 引发 ``RuntimeError: Event loop is closed`` / ``'NoneType' object has
# no attribute 'send'``：``asyncio.run()`` 在协程返回后立即关闭 loop，而
# asyncpg 的连接/传输对象往往在稍后被 GC 回收时才尝试在 loop 上调度清理
# 任务（``create_task``），此时 loop 已关闭，于是报错。
#
# 解决方案：CLI 全程复用同一个事件循环。``run_async`` 通过
# ``loop.run_until_complete`` 执行协程，引擎与连接始终绑定在同一个 loop
# 上，调用间不释放、不关闭。仅在 CLI 退出时（``shutdown_async``）先在
# loop 仍存活的状态下释放引擎（确保 asyncpg 连接被正确关闭），再关闭
# loop，从而避免任何对象在已关闭的 loop 上调度任务。
# ---------------------------------------------------------------------------

_loop: asyncio.AbstractEventLoop | None = None


def _get_loop() -> asyncio.AbstractEventLoop:
    """获取（必要时创建）CLI 专用的全局事件循环，跨调用复用。"""
    global _loop
    if _loop is None or _loop.is_closed():
        _loop = asyncio.new_event_loop()
        # 设为当前线程的默认 loop，供依赖 ``asyncio.get_event_loop()`` 的库使用
        asyncio.set_event_loop(_loop)
    return _loop


def run_async(coro: Awaitable[_T]) -> _T:
    """在全局事件循环上运行协程，循环在调用间保持存活。

    与 ``asyncio.run`` 不同，此处不会在协程返回后关闭事件循环，因此
    SQLAlchemy 异步引擎及其 asyncpg 连接池可安全复用，不会出现
    ``Event loop is closed`` 问题。循环仅在 :func:`shutdown_async` 中关闭。
    """
    return _get_loop().run_until_complete(coro)


async def _dispose_engine() -> None:
    from core.database.connection.pgsql import dispose_engine

    await dispose_engine()


def shutdown_async() -> None:
    """CLI 退出时释放引擎并关闭事件循环。

    必须先在 loop 存活时释放引擎，确保 asyncpg 连接被正确关闭，
    随后再关闭 loop，避免连接对象的 ``__del__`` 在已关闭的 loop 上报错。
    """
    global _loop
    if _loop is None or _loop.is_closed():
        return
    try:
        _loop.run_until_complete(_dispose_engine())
    except Exception as exc:
        # 释放过程中出错也要继续关闭 loop，避免泄漏；记录到 stderr 以便诊断
        print(f"警告: 引擎释放失败: {exc}", file=sys.stderr)
    _loop.close()
    _loop = None

# ---------------------------------------------------------------------------
# 密码哈希辅助（与前端登录逻辑保持一致）
# ---------------------------------------------------------------------------


def double_sha256_hex(value: str) -> str:
    """对字符串做两次 SHA-256，返回 64 字符 hex。"""
    first = hashlib.sha256(value.encode()).hexdigest()
    return hashlib.sha256(first.encode()).hexdigest()


# ---------------------------------------------------------------------------
# 输出辅助
# ---------------------------------------------------------------------------


def print_json(obj: Any) -> None:
    """以美化后的 JSON 输出到标准输出。"""
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def generate_random_password(length: int = 12) -> str:
    """生成包含大小写字母与数字的随机密码。"""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(chars) for _ in range(length))


def parse_json_or_prompt(data: str | None, prompt: str) -> dict[str, Any]:
    """从命令行参数或标准输入读取 JSON 数据。"""
    raw = data if data else input(prompt)
    return json.loads(raw)
