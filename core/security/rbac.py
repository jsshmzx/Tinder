"""RBAC（基于角色的访问控制）相关工具。

当前系统暂时定义三种角色：
- superadmin
- songlist_editor
- normal-user

并约定权限强弱：superadmin > songlist_editor > normal-user。
"""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    SUPERADMIN = "superadmin"
    SONGLIST_EDITOR = "songlist_editor"
    NORMAL_USER = "normal-user"


ROLE_LEVEL: dict[str, int] = {
    Role.NORMAL_USER.value: 1,
    Role.SONGLIST_EDITOR.value: 2,
    Role.SUPERADMIN.value: 3,
}


def normalize_role(role: str | None) -> str:
    """将未知/空角色归一为 normal-user，避免默认放行。"""
    if not role:
        return Role.NORMAL_USER.value
    return role


def has_min_role(user_role: str | None, required_role: str) -> bool:
    """判断 user_role 是否 >= required_role。"""
    user_level = ROLE_LEVEL.get(normalize_role(user_role), 0)
    required_level = ROLE_LEVEL.get(required_role, 0)
    return user_level >= required_level


def role_includes(user_role: str | None, allowed_roles: list[str]) -> bool:
    """允许使用旧的 allowed_roles 形式（显式列举），同时兼容层级角色。

规则：
- 如果 allowed_roles 明确包含某个角色，则仍然按“层级”判定是否包含。
  例如 allowed_roles=["songlist_editor"]，superadmin 也应被允许。
- 如果 allowed_roles 为空，则不放行。
"""
    if not allowed_roles:
        return False

    user_level = ROLE_LEVEL.get(normalize_role(user_role), 0)
    min_allowed_level: int | None = None
    for role in allowed_roles:
        level = ROLE_LEVEL.get(role)
        if level is None:
            continue
        if min_allowed_level is None or level < min_allowed_level:
            min_allowed_level = level

    if min_allowed_level is None:
        return False
    return user_level >= min_allowed_level

