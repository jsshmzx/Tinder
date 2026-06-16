"""SHA256 双重哈希密码模块。

客户端在发送前自行计算 SHA256(SHA256(明文)) → 64 字符 hex 字符串，
服务端直接存储和比对，不做额外哈希。
"""

import hmac


def hash_password(password: str) -> str:
    """接收客户端传来的 SHA256 hex 字符串，直接返回（服务端不额外哈希）。

    Args:
        password: 64 字符 hex 字符串（SHA256 双重哈希结果）

    Returns:
        原样返回，用于直接存入数据库
    """
    return password


def verify_password(password: str, stored_hash: str) -> bool:
    """常量时间比对密码 hex 字符串（防止 timing attack）。

    Args:
        password: 客户端传来的 SHA256 hex 字符串
        stored_hash: 数据库中存储的 SHA256 hex 字符串

    Returns:
        bool: 是否匹配
    """
    return hmac.compare_digest(password, stored_hash)
