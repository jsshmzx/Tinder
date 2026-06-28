"""日志查询的权限控制。

规则：
- 系统日志：仅 superadmin 可查看。
- 个人日志：
  - normal-user 只能查看自己的日志。
  - songlist_editor 只能查看自己的日志。
  - superadmin 可以查看所有人的日志。

后续如需扩展“部门管理员”等数据权限，可在此模块中增加 scope 计算逻辑。
"""

from fastapi import Depends, HTTPException, status

from core.middleware.auth.dependencies import get_current_user
from core.security.rbac import Role, has_min_role


class LogPermissionError(Exception):
    """日志权限异常。"""


SYSTEM_LOG_MIN_ROLE = Role.SUPERADMIN.value


def can_access_system_logs(user: dict) -> bool:
    """判断用户是否有权查看系统日志。"""
    return has_min_role(user.get("user_role"), SYSTEM_LOG_MIN_ROLE)


def get_permitted_user_uuids(
    current_user: dict, requested_user_uuid: str | None = None
) -> list[str] | None:
    """计算个人日志查询允许访问的用户 UUID 范围。

    返回值：
        - list[str]：明确限定在某些用户 UUID 内。
        - None：不做限定（管理员查看全部）。

    当普通用户尝试查看他人日志时抛出 403。
    """
    user_role = current_user.get("user_role")
    self_uuid = current_user.get("uuid")

    if has_min_role(user_role, Role.SUPERADMIN.value):
        # 管理员可查看全部，若指定了 user_uuid 则只查该用户
        return [requested_user_uuid] if requested_user_uuid else None

    # 非管理员只能查看自己
    if requested_user_uuid is not None and requested_user_uuid != self_uuid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权查看其他用户的个人日志",
        )
    if self_uuid is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无法识别当前用户身份",
        )
    return [self_uuid]


def require_system_log_access(user: dict = Depends(get_current_user)) -> dict:
    """FastAPI Depends：要求当前用户具有系统日志查看权限。"""
    if not can_access_system_logs(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权查看系统日志",
        )
    return user
