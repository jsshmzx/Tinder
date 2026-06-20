"""清理过期注销账号任务 — 每小时执行一次。"""

from datetime import datetime

from sqlalchemy import select

from core.database.connection.pgsql import get_session
from core.database.dao.refresh_tokens import RefreshTokensDAO
from core.database.dao.users import User
from core.helper.ContainerCustomLog.index import custom_log


async def cleanup_expired_deletions() -> None:
    """清理所有冷却期已满的注销账号。

    查询条件：current_status = 'pending_deletion' AND deletion_scheduled_at <= now()
    操作：撤销所有 refresh token → 物理删除用户记录。
    """
    now = datetime.now()

    # Step 1: 查找过期用户
    async with get_session() as session:
        result = await session.scalars(
            select(User).where(
                User.current_status == "pending_deletion",
                User.deletion_scheduled_at <= now,
            )
        )
        expired_users = result.all()

    if not expired_users:
        return

    expired_uuids = [str(u.uuid) for u in expired_users]

    # Step 2: 撤销所有 refresh token
    for uuid in expired_uuids:
        await RefreshTokensDAO.revoke_all_for_user(uuid)

    # Step 3: 物理删除用户
    async with get_session() as session:
        result = await session.scalars(
            select(User).where(User.uuid.in_(expired_uuids))
        )
        for user in result.all():
            await session.delete(user)
        await session.flush()

    custom_log("SUCCESS", f"[Cron] 清理过期注销账号: {len(expired_uuids)} 个")
