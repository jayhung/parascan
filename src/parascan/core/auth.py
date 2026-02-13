"""auth manager — attaches credentials to outgoing requests."""

from __future__ import annotations

import base64
from typing import Any

from parascan.core.config import AuthConfig


class AuthManager:
    """builds auth headers/cookies from config."""

    def __init__(self, config: AuthConfig) -> None:
        self._config = config

    def get_headers(self) -> dict[str, str]:
        """return headers dict to attach to every request."""
        headers: dict[str, str] = {}

        if self._config.bearer:
            headers["Authorization"] = f"Bearer {self._config.bearer}"

        if self._config.api_key_header and self._config.api_key_value:
            headers[self._config.api_key_header] = self._config.api_key_value

        if self._config.basic_username and self._config.basic_password:
            creds = f"{self._config.basic_username}:{self._config.basic_password}"
            encoded = base64.b64encode(creds.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        return headers

    def get_cookies(self) -> dict[str, str]:
        """return cookies dict to attach to every request."""
        cookies: dict[str, str] = {}
        if self._config.cookie:
            for pair in self._config.cookie.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cookies[k.strip()] = v.strip()
        return cookies

    def apply(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        """apply auth headers and cookies to a request kwargs dict."""
        headers = kwargs.get("headers", {})
        headers.update(self.get_headers())
        kwargs["headers"] = headers

        cookies = self.get_cookies()
        if cookies:
            existing = kwargs.get("cookies", {})
            existing.update(cookies)
            kwargs["cookies"] = existing

        return kwargs
