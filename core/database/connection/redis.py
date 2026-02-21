import os
import threading

import redis as redis_lib
from redis import Redis

from core.helper.ContainerCustomLog.index import custom_log

# 重连间隔（秒），每次失败后指数增长，最大不超过 _MAX_RETRY_INTERVAL
_INITIAL_RETRY_INTERVAL = 2
_MAX_RETRY_INTERVAL = 60


class RedisConnectionManager:
    """Redis 连接管理器。

    在应用启动时通过 :meth:`start` 建立连接，停止时通过 :meth:`stop` 关闭。
    若连接中途断开，后台线程将持续尝试重连，直到成功或管理器被停止。
    """

    def __init__(self) -> None:
        self._client: Redis | None = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._monitor_thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """建立初始连接并启动后台监控线程。"""
        self._stop_event.clear()
        self._connect()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="redis-monitor"
        )
        self._monitor_thread.start()

    def stop(self) -> None:
        """停止监控线程并关闭连接。"""
        self._stop_event.set()
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=5)
        with self._lock:
            self._close()
        custom_log("SUCCESS", "Redis 连接已关闭")

    def get_client(self) -> Redis | None:
        """返回当前活跃的 Redis 客户端，若尚未连接则返回 None。"""
        with self._lock:
            return self._client

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_url(self) -> str:
        url = os.getenv("REDIS_URL")
        if not url:
            raise EnvironmentError("环境变量 REDIS_URL 未设置")
        return url

    def _connect(self) -> bool:
        """尝试建立连接，成功返回 True，失败返回 False。"""
        try:
            url = self._get_url()
            client = redis_lib.from_url(url, decode_responses=True)
            # 立即执行 PING 验证连通性
            client.ping()
            with self._lock:
                self._close()
                self._client = client
            custom_log("SUCCESS", "Redis 连接成功")
            return True
        except Exception as exc:
            custom_log("ERROR", f"Redis 连接失败: {exc}")
            return False

    def _close(self) -> None:
        """关闭当前连接（不加锁，调用方负责加锁）。"""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def _is_alive(self) -> bool:
        """检查 Redis 连接是否仍然存活。"""
        with self._lock:
            if self._client is None:
                return False
        try:
            with self._lock:
                self._client.ping()
            return True
        except Exception:
            return False

    def _monitor_loop(self) -> None:
        """后台线程：定期检查连接健康，断开时自动重连。"""
        retry_interval = _INITIAL_RETRY_INTERVAL
        while not self._stop_event.is_set():
            # 每 10 秒做一次心跳检测
            self._stop_event.wait(timeout=10)
            if self._stop_event.is_set():
                break
            if not self._is_alive():
                custom_log("WARNING", "Redis 连接已断开，正在尝试重连...")
                while not self._stop_event.is_set():
                    if self._connect():
                        retry_interval = _INITIAL_RETRY_INTERVAL
                        break
                    custom_log(
                        "WARNING",
                        f"Redis 重连失败，{retry_interval} 秒后重试...",
                    )
                    self._stop_event.wait(timeout=retry_interval)
                    retry_interval = min(retry_interval * 2, _MAX_RETRY_INTERVAL)


# 全局单例
redis_conn = RedisConnectionManager()
