"""Unit tests — core.cron.scheduler (start/stop, mocked APScheduler)."""

from unittest.mock import patch


def test_start_registers_cleanup_job(monkeypatch):
    """start() adds the cleanup_expired_deletions job to the scheduler."""
    from core.cron.scheduler import scheduler

    jobs_added = []
    original_add_job = scheduler.add_job

    def capture_add_job(func, trigger=None, hours=None, id=None, replace_existing=None):
        jobs_added.append({
            "func": func,
            "trigger": trigger,
            "hours": hours,
            "id": id,
        })

    monkeypatch.setattr(scheduler, "add_job", capture_add_job)
    monkeypatch.setattr(scheduler, "start", lambda: None)

    from core.cron.scheduler import start
    start()

    assert len(jobs_added) == 1
    job = jobs_added[0]
    assert job["id"] == "cleanup_expired_deletions"
    assert job["trigger"] == "interval"
    assert job["hours"] is not None  # should be from settings


def test_stop_calls_shutdown(monkeypatch):
    """stop() calls scheduler.shutdown(wait=False)."""
    from core.cron.scheduler import scheduler

    shutdown_called = []

    def capture_shutdown(wait=False):
        shutdown_called.append(wait)

    monkeypatch.setattr(scheduler, "shutdown", capture_shutdown)

    from core.cron.scheduler import stop
    stop()

    assert len(shutdown_called) == 1
    assert shutdown_called[0] is False


def test_start_logs_success(monkeypatch, capsys):
    """start() logs SUCCESS message."""
    from core.cron.scheduler import scheduler

    monkeypatch.setattr(scheduler, "add_job", lambda *a, **kw: None)
    monkeypatch.setattr(scheduler, "start", lambda: None)

    from core.cron.scheduler import start
    start()

    out = capsys.readouterr().out
    assert "[SUCCESS]" in out
    assert "定时任务调度器已启动" in out


def test_stop_logs_success(monkeypatch, capsys):
    """stop() logs SUCCESS message."""
    from core.cron.scheduler import scheduler

    monkeypatch.setattr(scheduler, "shutdown", lambda wait=False: None)

    from core.cron.scheduler import stop
    stop()

    out = capsys.readouterr().out
    assert "[SUCCESS]" in out
    assert "定时任务调度器已停止" in out


def test_scheduler_is_asyncio_scheduler():
    """The scheduler is an AsyncIOScheduler instance."""
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from core.cron.scheduler import scheduler

    assert isinstance(scheduler, AsyncIOScheduler)
