"""RBAC 角色常量与权限层级定义。

角色层级（从低到高）：
    normal-user (1) < songlist_editor (2) < superadmin (3)

superadmin 拥有所有权限；songlist_editor 拥有 normal-user 的全部权限。
"""

# ---------------------------------------------------------------------------
# 角色常量
# ---------------------------------------------------------------------------

SUPERADMIN = "superadmin"
SONGLIST_EDITOR = "songlist_editor"
NORMAL_USER = "normal-user"

# 角色层级映射（数值越大权限越高）
_ROLE_HIERARCHY: dict[str, int] = {
    NORMAL_USER: 1,
    SONGLIST_EDITOR: 2,
    SUPERADMIN: 3,
}

# 所有有效角色列表（按层级从低到高排列）
ALL_ROLES: list[str] = [NORMAL_USER, SONGLIST_EDITOR, SUPERADMIN]


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def get_role_level(role: str | None) -> int:
    """获取角色对应的权限层级数值，未知角色或 None 返回 0。

    示例：
        get_role_level("superadmin")      → 3
        get_role_level("songlist_editor") → 2
        get_role_level("normal-user")     → 1
        get_role_level(None)              → 0
    """
    return _ROLE_HIERARCHY.get(role or "", 0)


def has_permission(user_role: str | None, required_role: str) -> bool:
    """判断用户角色是否满足所需角色的权限要求（基于层级比较）。

    规则：用户角色层级 >= 所需角色层级时，视为有权限。

    示例：
        has_permission("superadmin", "songlist_editor")  → True
        has_permission("songlist_editor", "superadmin")  → False
        has_permission("normal-user", "normal-user")     → True
        has_permission(None, "normal-user")              → False
    """
    return get_role_level(user_role) >= get_role_level(required_role)


def is_valid_role(role: str) -> bool:
    """检查角色字符串是否为有效的 RBAC 角色。"""
    return role in _ROLE_HIERARCHY
