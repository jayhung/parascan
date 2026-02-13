"""scope enforcement — prevents requests to out-of-scope targets."""

from __future__ import annotations

from urllib.parse import urlparse

from parascan.core.config import ScopeConfig


class ScopeEnforcer:
    """validates URLs against allowed domains and paths."""

    def __init__(self, config: ScopeConfig) -> None:
        self._allowed_domains = [d.lower() for d in config.allowed_domains]
        self._allowed_paths = config.allowed_paths
        self._excluded_paths = config.excluded_paths

    def is_in_scope(self, url: str) -> bool:
        """check if a URL is within the configured scope."""
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        # check domain
        if self._allowed_domains and hostname not in self._allowed_domains:
            return False

        path = parsed.path or "/"

        # check excluded paths
        for excluded in self._excluded_paths:
            if path.startswith(excluded):
                return False

        # check allowed paths (empty = all allowed)
        if self._allowed_paths:
            if not any(path.startswith(p) for p in self._allowed_paths):
                return False

        return True
