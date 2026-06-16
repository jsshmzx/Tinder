"""定时任务调度器 — 负责注册和启停所有定时任务。"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from core.config import settings
from core.helper.ContainerCustomLog.index import custom_log

scheduler = AsyncIOScheduler()


def start() -> None:
    """启动调度器并注册所有定时任务。"""
    from core.cron.tasks.cleanup_users import cleanup_expired_deletions

    scheduler.add_job(
        cleanup_expired_deletions,
        trigger="interval",
        hours=settings.CRON_CLEANUP_INTERVAL_HOURS,
        id="cleanup_expired_deletions",
        replace_existing=True,
    )

    scheduler.start()
    custom_log("SUCCESS", "[Cron] 定时任务调度器已启动")


def stop() -> None:
    """停止调度器。"""
    scheduler.shutdown(wait=False)
    custom_log("SUCCESS", "[Cron] 定时任务调度器已停止")
