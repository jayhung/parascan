"""CSRF scanner — checks for missing CSRF tokens and SameSite cookie issues."""

from __future__ import annotations

from typing import Any

import httpx
import yaml

from parascan.scanners.base import BaseScanner, ScanResult


REMEDIATION_TOKEN = (
    "Implement anti-CSRF tokens on all state-changing endpoints. Use your "
    "framework's built-in CSRF protection (e.g., Django's {% csrf_token %}, "
    "Express csurf, Spring Security CSRF). Tokens should be unique per session "
    "and validated server-side on every state-changing request."
)

REMEDIATION_COOKIE = (
    "Set the SameSite attribute explicitly on all cookies. Use 'SameSite=Lax' "
    "as the minimum (or 'Strict' for sensitive cookies). Always pair "
    "'SameSite=None' with the 'Secure' flag. Set 'HttpOnly' on session cookies."
)

SOC2 = "CC6.8"


class CSRFScanner(BaseScanner):
    module_name = "csrf"
    description = "CSRF token and SameSite cookie checks"

    def __init__(self) -> None:
        super().__init__()
        self._payloads_data = self._load_payloads()

    def _load_payloads(self) -> dict:
        import pathlib

        path = pathlib.Path(__file__).parent.parent / "payloads" / "csrf.yaml"
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]
        method = endpoint.get("method", "GET").upper()

        state_changing = self._payloads_data.get("state_changing_methods", [])
        if method not in state_changing:
            return results

        # check if the endpoint accepts requests without CSRF tokens
        token_fields = self._payloads_data.get("token_field_names", [])
        token_headers = self._payloads_data.get("token_header_names", [])

        # first, get the page to check for CSRF tokens in forms
        page_resp = await self._request(client, "GET", url)
        has_csrf_in_form = False
        if page_resp:
            body_lower = page_resp.text.lower()
            for field in token_fields:
                if field.lower() in body_lower:
                    has_csrf_in_form = True
                    break

        # attempt the state-changing request without any CSRF token
        params = endpoint.get("params", {})
        # remove any CSRF-like params
        clean_params = {
            k: v for k, v in params.items()
            if k.lower() not in {f.lower() for f in token_fields}
        }

        resp = await self._request(
            client, method, url,
            data=clean_params if method in ("POST", "PUT", "PATCH") else None,
            params=clean_params if method == "DELETE" else None,
        )

        if resp is None:
            return results

        # if the request succeeded without a CSRF token, flag it
        if resp.status_code in (200, 201, 202, 204, 301, 302):
            if not has_csrf_in_form:
                results.append(ScanResult(
                    module=self.module_name,
                    severity="medium",
                    title=f"Missing CSRF protection on {method} {url}",
                    description=(
                        f"The {method} endpoint accepts requests without a CSRF token. "
                        f"No CSRF token field was found in the associated form. "
                        f"An attacker could forge cross-site requests."
                    ),
                    evidence=f"HTTP {resp.status_code} returned without CSRF token",
                    request_data=self._format_request(method, url, data=clean_params),
                    response_data=self._format_response(resp),
                    remediation=REMEDIATION_TOKEN,
                    soc2_criteria=SOC2,
                ))

        # check SameSite cookie attribute
        cookie_results = self._check_samesite_cookies(resp)
        results.extend(cookie_results)

        return results

    def _check_samesite_cookies(self, resp: httpx.Response) -> list[ScanResult]:
        """check if Set-Cookie headers have proper SameSite attribute."""
        results: list[ScanResult] = []
        set_cookie_headers = resp.headers.get_list("set-cookie")

        for cookie_header in set_cookie_headers:
            cookie_name = cookie_header.split("=")[0].strip() if "=" in cookie_header else "unknown"
            lower = cookie_header.lower()

            if "samesite=none" in lower:
                if "secure" not in lower:
                    results.append(ScanResult(
                        module=self.module_name,
                        severity="medium",
                        title=f"Cookie '{cookie_name}' has SameSite=None without Secure",
                        description=(
                            f"The cookie '{cookie_name}' is set with SameSite=None but "
                            f"without the Secure flag, making it vulnerable to CSRF."
                        ),
                        evidence=f"Set-Cookie: {cookie_header}",
                        remediation=REMEDIATION_COOKIE,
                        soc2_criteria=SOC2,
                    ))
            elif "samesite" not in lower:
                results.append(ScanResult(
                    module=self.module_name,
                    severity="low",
                    title=f"Cookie '{cookie_name}' missing SameSite attribute",
                    description=(
                        f"The cookie '{cookie_name}' does not set the SameSite attribute. "
                        f"Browsers default to Lax, but explicit setting is recommended."
                    ),
                    evidence=f"Set-Cookie: {cookie_header}",
                    remediation=REMEDIATION_COOKIE,
                    soc2_criteria=SOC2,
                ))

        return results
