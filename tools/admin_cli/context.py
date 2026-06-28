"""运行时上下文：保存当前模式、API 客户端、DB 客户端。"""

from __future__ import annotations

import argparse
import getpass
from dataclasses import dataclass
from typing import Any

from admin_cli.api_client import ApiClient
from admin_cli.base import double_sha256_hex
from admin_cli.db_client import DbClient


@dataclass
class AdminContext:
    """CLI 全局状态。"""

    args: argparse.Namespace
    api: ApiClient | None = None
    db: DbClient | None = None

    @property
    def mode(self) -> str:
        return self.args.mode

    def require_api(self) -> ApiClient:
        if self.api is None:
            raise RuntimeError("当前不是 API 模式")
        return self.api

    def require_db(self) -> DbClient:
        if self.db is None:
            raise RuntimeError("当前不是 DB 模式")
        return self.db

    # ------------------------------------------------------------------
    # 登录与超级密码
    # ------------------------------------------------------------------

    def ensure_login(self) -> None:
        """API 模式下若未登录则交互式提示。"""
        if self.mode != "api" or self.api is None:
            return
        if self.api.token:
            return
        username = self.args.username or input("用户名: ")
        password = self.args.password or getpass.getpass("密码: ")
        self.api.login(username, password)
        print("登录成功")

    def super_password(self, override: str | None = None) -> str:
        return override or self.args.super_password or getpass.getpass("超级密码: ")
