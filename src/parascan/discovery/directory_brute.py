"""directory/endpoint brute-forcing with wordlists."""

from __future__ import annotations

import logging
import pathlib
from typing import Any

import httpx

from parascan.core.scope import ScopeEnforcer

logger = logging.getLogger("parascan.discovery.dirbrute")

DEFAULT_WORDLIST = pathlib.Path(__file__).parent.parent / "wordlists" / "directories.txt"


async def brute_force_directories(
    client: httpx.AsyncClient,
    base_url: str,
    scope: ScopeEnforcer,
    wordlist_path: str | pathlib.Path | None = None,
    max_entries: int = 200,
) -> list[dict[str, Any]]:
    """
    Try common directory/endpoint paths against the target.

    Returns endpoint dicts for paths that return non-404 responses.
    """
    path = pathlib.Path(wordlist_path) if wordlist_path else DEFAULT_WORDLIST
    if not path.exists():
        return []

    with open(path) as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    words = words[:max_entries]
    endpoints: list[dict[str, Any]] = []
    base = base_url.rstrip("/")

    for word in words:
        url = f"{base}/{word}"
        if not scope.is_in_scope(url):
            continue

        try:
            resp = await client.get(url, follow_redirects=False)
            if resp.status_code not in (404, 405, 502, 503):
                endpoints.append({
                    "url": url,
                    "method": "GET",
                    "params": {},
                })
        except Exception:
            continue

    return endpoints
