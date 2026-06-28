"""公共基础：密码哈希、JSON 输出、随机密码。"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

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
