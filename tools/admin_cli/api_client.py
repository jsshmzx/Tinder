"""API 模式客户端：通过 HTTP 调用后端管理员接口。"""

from __future__ import annotations

from typing import Any


class ApiClient:
    """通过 HTTP API 调用后端的管理员客户端。"""

    def __init__(self, base_url: str) -> None:
        import httpx

        self.base_url = base_url.rstrip("/")
        self.token: str | None = None
        self._httpx = httpx
        self._client: Any | None = None

    def _client_sync(self) -> Any:
        if self._client is None:
            self._client = self._httpx.Client(base_url=self.base_url, timeout=30)
        return self._client

    def login(self, username: str, password: str) -> dict[str, Any]:
        from admin_cli.base import double_sha256_hex

        payload = {"username": username, "password": double_sha256_hex(password)}
        resp = self._client_sync().post("/api/v1/auth/login", json=payload)
        resp.raise_for_status()
        data = resp.json()
        self.token = data.get("access_token")
        return data

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> Any:
        if not self.token:
            raise RuntimeError("尚未登录，请先调用 login()")
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = self._client_sync().request(
            method, path, params=params, json=json_data, headers=headers
        )
        try:
            resp.raise_for_status()
        except Exception as exc:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            raise RuntimeError(f"API 错误 ({resp.status_code}): {detail}") from exc
        if resp.status_code == 204:
            return None
        return resp.json()

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, json_data: dict[str, Any] | None = None) -> Any:
        return self.request("POST", path, json_data=json_data)

    def patch(self, path: str, json_data: dict[str, Any] | None = None) -> Any:
        return self.request("PATCH", path, json_data=json_data)

    def delete(self, path: str, json_data: dict[str, Any] | None = None) -> Any:
        return self.request("DELETE", path, json_data=json_data)
