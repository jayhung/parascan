"""basic web spider for endpoint discovery."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from parascan.core.scope import ScopeEnforcer

logger = logging.getLogger("parascan.crawler")


async def crawl(
    client: httpx.AsyncClient,
    start_url: str,
    scope: ScopeEnforcer,
    scan_id: int | None = None,
    max_pages: int = 50,
    max_depth: int = 5,
) -> list[dict[str, Any]]:
    """
    Crawl a target to discover endpoints.

    Returns a list of endpoint dicts with url, method, and params keys.
    max_depth limits how many link-hops from the start URL to follow.
    """
    from parascan.core.state import save_scan_event

    async def _event(level: str, msg: str, detail: str | None = None) -> None:
        if scan_id is not None:
            await save_scan_event(scan_id, level, "discovery.crawl", msg, detail)

    visited: set[str] = set()
    to_visit: list[tuple[str, int]] = [(start_url, 0)]
    endpoints: list[dict[str, Any]] = []
    seen_endpoints: set[str] = set()

    while to_visit and len(visited) < max_pages:
        url, depth = to_visit.pop(0)

        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if normalized in visited:
            continue

        if not scope.is_in_scope(url):
            logger.info("out of scope, skipping: %s", url)
            continue

        visited.add(normalized)

        try:
            resp = await client.get(url, follow_redirects=True)
        except Exception as e:
            logger.warning("crawl request failed for %s: %s", url, e)
            await _event("warning", f"request failed for {url}", str(e))
            continue

        content_type = resp.headers.get("content-type", "")
        logger.info(
            "crawled %s — HTTP %d, content-type: %s",
            url, resp.status_code, content_type,
        )

        if "html" not in content_type and "json" not in content_type:
            logger.info("skipping non-html/json response: %s", content_type)
            continue

        key = f"GET:{normalized}"
        if key not in seen_endpoints:
            seen_endpoints.add(key)
            param_dict = _extract_query_params(parsed.query)
            endpoints.append({"url": normalized, "method": "GET", "params": param_dict})

        if "html" not in content_type:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        if depth < max_depth:
            links_found = 0
            links_queued = 0
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                links_found += 1
                full_url = urljoin(url, href)
                full_parsed = urlparse(full_url)
                clean = f"{full_parsed.scheme}://{full_parsed.netloc}{full_parsed.path}"
                if clean not in visited and scope.is_in_scope(full_url):
                    to_visit.append((full_url, depth + 1))
                    links_queued += 1
            logger.info(
                "depth %d: found %d links, queued %d in-scope",
                depth, links_found, links_queued,
            )

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            form_url = urljoin(url, action) if action else url

            form_params: dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    form_params[name] = inp.get("value", "")

            form_key = f"{method}:{form_url}"
            if form_key not in seen_endpoints:
                seen_endpoints.add(form_key)
                endpoints.append({
                    "url": form_url,
                    "method": method,
                    "params": form_params,
                })
                logger.info("discovered form: %s %s", method, form_url)
                await _event("info", f"discovered form: {method} {form_url}")

    logger.info("crawl complete: %d endpoint(s) from %d page(s)", len(endpoints), len(visited))
    return endpoints


def _extract_query_params(query: str) -> dict[str, str]:
    """parse query string into a dict."""
    params: dict[str, str] = {}
    if not query:
        return params
    for pair in query.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k] = v
        else:
            params[pair] = ""
    return params
