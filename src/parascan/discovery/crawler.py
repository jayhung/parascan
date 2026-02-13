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
    max_pages: int = 50,
) -> list[dict[str, Any]]:
    """
    Crawl a target to discover endpoints.

    Returns a list of endpoint dicts with url, method, and params keys.
    """
    visited: set[str] = set()
    to_visit: list[str] = [start_url]
    endpoints: list[dict[str, Any]] = []
    seen_endpoints: set[str] = set()

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)

        # normalize
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if normalized in visited:
            continue

        if not scope.is_in_scope(url):
            continue

        visited.add(normalized)

        try:
            resp = await client.get(url, follow_redirects=True)
        except Exception as e:
            logger.debug(f"crawl failed for {url}: {e}")
            continue

        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type and "json" not in content_type:
            continue

        # register this page as a GET endpoint
        key = f"GET:{normalized}"
        if key not in seen_endpoints:
            seen_endpoints.add(key)
            params = dict(parsed.query.split("=", 1) for _ in [] for _ in [])  # placeholder
            # extract query params
            param_dict = _extract_query_params(parsed.query)
            endpoints.append({"url": normalized, "method": "GET", "params": param_dict})

        if "html" not in content_type:
            continue

        # parse HTML for links and forms
        soup = BeautifulSoup(resp.text, "html.parser")

        # extract links
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full_url = urljoin(url, href)
            full_parsed = urlparse(full_url)
            clean = f"{full_parsed.scheme}://{full_parsed.netloc}{full_parsed.path}"
            if clean not in visited and scope.is_in_scope(full_url):
                to_visit.append(full_url)

        # extract forms
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
