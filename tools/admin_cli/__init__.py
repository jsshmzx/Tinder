"""Tinder 管理 CLI 子模块包。

将原 ``tools/admin_cli.py``（955 行单体）按职责拆分为：
- ``base``        密码哈希与公共工具
- ``api_client``  API 模式客户端
- ``db_client``   DB 模式客户端
- ``parsers``     argparse 子命令解析器
- ``menu``        交互式 Q&A 辅助
- ``users``       用户管理命令
- ``questions``   注册问题管理命令
- ``logs``        日志查询命令
- ``config``      系统配置命令
- ``db``          直接 SQL 命令
- ``shell``       交互式 Shell 循环
"""

from admin_cli.base import double_sha256_hex, print_json
from admin_cli.api_client import ApiClient
from admin_cli.db_client import DbClient

__all__ = [
    "ApiClient",
    "DbClient",
    "double_sha256_hex",
    "print_json",
]
