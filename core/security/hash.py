"""密码哈希模块 — 桥接到 core.security.password。

现有调用方（auth、users、admin）的 import 路径不变，
内部逻辑已切换为 SHA256 双重哈希直通。
"""

from core.security.password import hash_password as _hash
from core.security.password import verify_password as _verify


def get_password_hash(password: str) -> str:
    """对密码进行哈希处理（SHA256 双重哈希，服务端直接存储）。

    Args:
        password: 64 字符 hex 字符串（客户端已做 SHA256 双重哈希）

    Returns:
        原样返回 hex 字符串
    """
    return _hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证明文 SHA256 hex 字符串与存储值是否匹配（常量时间比对）。

    Args:
        plain_password: 客户端传来的 SHA256 hex 字符串
        hashed_password: 数据库中存储的 SHA256 hex 字符串

    Returns:
        bool: 是否匹配
    """
    return _verify(plain_password, hashed_password)
