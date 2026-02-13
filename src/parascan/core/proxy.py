"""proxy support for routing traffic through intercepting proxies."""

from __future__ import annotations

from parascan.core.config import ProxyConfig


class ProxyManager:
    """manages proxy configuration for httpx client."""

    def __init__(self, config: ProxyConfig) -> None:
        self._url = config.url

    @property
    def is_enabled(self) -> bool:
        return self._url is not None

    def get_proxy_url(self) -> str | None:
        return self._url

    def get_transport_kwargs(self) -> dict:
        """return kwargs to pass to httpx.AsyncClient for proxy support."""
        if self._url:
            return {"proxy": self._url, "verify": False}
        return {}
