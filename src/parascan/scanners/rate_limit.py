"""rate limiting / brute-force scanner — checks for missing rate limiting on endpoints.

This scanner is opt-in only (default_enabled = False) because it sends rapid
burst requests that could trigger WAF bans or account lockouts.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from parascan.scanners.base import BaseScanner, ScanResult


REMEDIATION_RATE_LIMIT = (
    "Implement rate limiting on all endpoints, especially authentication endpoints. "
    "Use a middleware or API gateway that enforces per-IP and per-user request limits. "
    "Return HTTP 429 (Too Many Requests) with a Retry-After header when limits are "
    "exceeded. Popular tools: nginx rate limiting, Express express-rate-limit, "
    "Django django-ratelimit, or cloud WAF rules."
)

REMEDIATION_LOCKOUT = (
    "Implement account lockout or progressive delays after repeated failed login "
    "attempts. Lock accounts after 5-10 failed attempts with a 15-30 minute cooldown. "
    "Consider CAPTCHA after 3 failures. Alert on brute-force patterns. "
    "Never reveal whether the username or password was incorrect."
)

SOC2 = "CC7.2"

# number of rapid requests to test rate limiting
BURST_COUNT = 20


class RateLimitScanner(BaseScanner):
    module_name = "rate-limit"
    description = "Rate limiting and brute-force protection checks (opt-in)"
    default_enabled = False

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]
        method = endpoint.get("method", "GET")

        # test general rate limiting by sending rapid burst requests
        rate_result = await self._test_rate_limiting(client, url, method)
        if rate_result:
            results.append(rate_result)

        # test login endpoint brute-force protection
        login_result = await self._test_login_lockout(client, url, method)
        if login_result:
            results.append(login_result)

        return results

    async def _test_rate_limiting(
        self, client: httpx.AsyncClient, url: str, method: str
    ) -> ScanResult | None:
        """send rapid burst of identical requests and check for 429 or blocking."""
        statuses: list[int] = []

        for _ in range(BURST_COUNT):
            try:
                resp = await client.request(method, url)
                statuses.append(resp.status_code)
            except Exception:
                statuses.append(0)

        # check if any request was rate-limited
        rate_limited = sum(1 for s in statuses if s == 429)
        blocked = sum(1 for s in statuses if s in (403, 503))
        successful = sum(1 for s in statuses if 200 <= s < 400)

        if rate_limited == 0 and blocked == 0 and successful == BURST_COUNT:
            return ScanResult(
                module=self.module_name,
                severity="medium",
                title=f"No rate limiting detected on {url}",
                description=(
                    f"Sent {BURST_COUNT} rapid requests to {url} and all returned "
                    f"successful responses. No HTTP 429 or blocking was observed. "
                    f"The endpoint may lack rate limiting protection."
                ),
                evidence=(
                    f"All {BURST_COUNT} requests returned 2xx/3xx. "
                    f"Status distribution: {_summarize_statuses(statuses)}"
                ),
                request_data=f"{BURST_COUNT}x {method} {url}",
                remediation=REMEDIATION_RATE_LIMIT,
                soc2_criteria=SOC2,
            )

        return None

    async def _test_login_lockout(
        self, client: httpx.AsyncClient, url: str, method: str
    ) -> ScanResult | None:
        """test if login-like endpoints enforce account lockout."""
        # only test POST endpoints that look like login/auth
        if method != "POST":
            return None

        url_lower = url.lower()
        login_keywords = [
            "login", "signin", "sign-in", "auth", "authenticate",
            "session", "token", "oauth",
        ]
        is_login = any(kw in url_lower for kw in login_keywords)
        if not is_login:
            return None

        # send multiple failed login attempts
        failed_count = 10
        statuses: list[int] = []

        for i in range(failed_count):
            try:
                resp = await client.request(
                    "POST", url,
                    json={"username": "admin", "password": f"wrong_password_{i}"},
                    headers={"Content-Type": "application/json"},
                )
                statuses.append(resp.status_code)
            except Exception:
                statuses.append(0)

        # check if the endpoint ever blocked us
        blocked = sum(1 for s in statuses if s in (429, 403, 423))

        if blocked == 0:
            # no lockout after repeated failures
            return ScanResult(
                module=self.module_name,
                severity="medium",
                title=f"No account lockout on login endpoint {url}",
                description=(
                    f"Sent {failed_count} failed login attempts and none were blocked "
                    f"with 429/403/423. The endpoint may lack brute-force protection."
                ),
                evidence=(
                    f"{failed_count} failed attempts, no blocking. "
                    f"Statuses: {_summarize_statuses(statuses)}"
                ),
                request_data=f"{failed_count}x POST {url} with invalid credentials",
                remediation=REMEDIATION_LOCKOUT,
                soc2_criteria=SOC2,
            )

        return None


def _summarize_statuses(statuses: list[int]) -> str:
    """summarize a list of HTTP status codes."""
    counts: dict[int, int] = {}
    for s in statuses:
        counts[s] = counts.get(s, 0) + 1
    return ", ".join(f"{code}: {count}x" for code, count in sorted(counts.items()))
