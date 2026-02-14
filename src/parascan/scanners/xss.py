"""reflected XSS scanner — injects payloads and checks for reflection."""

from __future__ import annotations

from typing import Any

import httpx

from parascan.scanners.base import BaseScanner, ScanResult


REMEDIATION = (
    "Encode all user-supplied data before rendering it in HTML. Use context-aware "
    "output encoding (HTML entity encoding for body, attribute encoding for attributes, "
    "JavaScript encoding for script contexts). Implement a Content-Security-Policy (CSP) "
    "header to restrict inline script execution. Use your framework's built-in auto-escaping."
)

SOC2 = "CC6.8"


class XSSScanner(BaseScanner):
    module_name = "xss"
    description = "Reflected cross-site scripting detection"

    # unique canary to detect reflection
    CANARY = "parascan_xss_7f3a"

    def __init__(self) -> None:
        super().__init__()
        self._payloads = self.load_payloads("xss.yaml")

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        params = endpoint.get("params", {})

        if not params:
            params = {"q": "test", "search": "test"}

        for param_name in params:
            # first check if our canary is reflected at all
            canary_params = {**params, param_name: self.CANARY}

            if method == "GET":
                resp = await self._request(client, method, url, params=canary_params)
            else:
                resp = await self._request(client, method, url, data=canary_params)

            if resp is None or self.CANARY not in resp.text:
                continue  # input not reflected, skip XSS checks

            # input is reflected — test actual XSS payloads
            for payload in self._payloads[:10]:
                injected = {**params, param_name: payload}

                if method == "GET":
                    resp = await self._request(client, method, url, params=injected)
                else:
                    resp = await self._request(client, method, url, data=injected)

                if resp is None:
                    continue

                # check if payload appears unencoded in response
                if payload in resp.text:
                    results.append(ScanResult(
                        module=self.module_name,
                        severity="high",
                        title=f"Reflected XSS in parameter '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' reflects user input without "
                            f"proper encoding. The XSS payload was found verbatim in the "
                            f"response body."
                        ),
                        evidence=f"Payload reflected: {payload}",
                        request_data=self._format_request(method, url, params=injected),
                        response_data=self._format_response(resp),
                        remediation=REMEDIATION,
                        soc2_criteria=SOC2,
                    ))
                    break  # one finding per parameter

                # check for partial reflection (html chars not encoded)
                if _has_unencoded_html(resp.text, payload):
                    results.append(ScanResult(
                        module=self.module_name,
                        severity="medium",
                        title=f"Potential XSS in parameter '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' reflects user input with "
                            f"partial encoding. HTML special characters may not be "
                            f"fully sanitized."
                        ),
                        evidence=f"Partial payload reflected for: {payload}",
                        request_data=self._format_request(method, url, params=injected),
                        response_data=self._format_response(resp),
                        remediation=REMEDIATION,
                        soc2_criteria=SOC2,
                    ))
                    break

        return results


def _has_unencoded_html(body: str, payload: str) -> bool:
    """check if HTML-significant chars from the payload appear unencoded."""
    dangerous_chars = ["<script>", "onerror=", "onload=", "javascript:", "<img", "<svg"]
    for char in dangerous_chars:
        if char in payload.lower() and char in body.lower():
            return True
    return False
