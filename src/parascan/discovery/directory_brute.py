"""directory/endpoint brute-forcing with wordlists."""

from __future__ import annotations

import logging
import pathlib
from typing import Any

import httpx

from parascan.core.scope import ScopeEnforcer
from parascan.core.soft404 import Soft404Detector

logger = logging.getLogger("parascan.discovery.dirbrute")

DEFAULT_WORDLIST = pathlib.Path(__file__).parent.parent / "wordlists" / "directories.txt"


async def brute_force_directories(
    client: httpx.AsyncClient,
    base_url: str,
    scope: ScopeEnforcer,
    scan_id: int | None = None,
    wordlist_path: str | pathlib.Path | None = None,
    max_entries: int = 200,
    soft404: Soft404Detector | None = None,
) -> list[dict[str, Any]]:
    """
    Try common directory/endpoint paths against the target.

    Returns endpoint dicts for paths that return non-404 responses.
    """
    from parascan.core.state import save_scan_event

    async def _event(level: str, msg: str, detail: str | None = None) -> None:
        if scan_id is not None:
            await save_scan_event(scan_id, level, "discovery.brute", msg, detail)

    path = pathlib.Path(wordlist_path) if wordlist_path else DEFAULT_WORDLIST
    if not path.exists():
        logger.warning("wordlist not found at %s", path)
        await _event("error", f"wordlist not found at {path}")
        return []

    with open(path) as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    words = words[:max_entries]
    logger.info("brute-forcing %d paths against %s", len(words), base_url)
    endpoints: list[dict[str, Any]] = []
    base = base_url.rstrip("/")
    errors = 0

    for word in words:
        url = f"{base}/{word}"
        if not scope.is_in_scope(url):
            continue

        try:
            resp = await client.get(url, follow_redirects=False)
            if resp.status_code not in (404, 405, 502, 503):
                if soft404 and soft404.is_soft_404(resp):
                    logger.debug("soft-404 filtered: %s", word)
                    continue
                logger.info("found: %s → HTTP %d", word, resp.status_code)
                endpoints.append({
                    "url": url,
                    "method": "GET",
                    "params": {},
                })
                await _event("info", f"found /{word} → HTTP {resp.status_code}")
        except Exception as e:
            errors += 1
            if errors <= 3:
                logger.warning("brute-force request failed for /%s: %s", word, e)
            elif errors == 4:
                logger.warning("suppressing further brute-force errors...")
            continue

    if errors:
        await _event("warning", f"{errors} request(s) failed during brute-force")

    logger.info(
        "brute-force complete: %d hit(s) from %d paths (%d errors)",
        len(endpoints), len(words), errors,
    )
    return endpoints
