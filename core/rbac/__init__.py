"""RBAC 鉴权模块。

提供角色常量、层级比较和有效性检查工具。
"""

from core.rbac.roles import (
    ALL_ROLES,
    NORMAL_USER,
    SONGLIST_EDITOR,
    SUPERADMIN,
    get_role_level,
    has_permission,
    is_valid_role,
)

__all__ = [
    "ALL_ROLES",
    "NORMAL_USER",
    "SONGLIST_EDITOR",
    "SUPERADMIN",
    "get_role_level",
    "has_permission",
    "is_valid_role",
]
