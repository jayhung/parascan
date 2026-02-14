"""open redirect scanner — detects unvalidated redirect vulnerabilities."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx
import yaml

from parascan.scanners.base import BaseScanner, ScanResult


REMEDIATION = (
    "Validate all redirect targets against an allowlist of trusted domains. "
    "Use relative URLs for internal redirects instead of accepting full URLs. "
    "If dynamic redirect targets are required, map them to predefined safe "
    "destinations on the server side rather than accepting arbitrary URLs."
)

SOC2 = "CC6.6"


class OpenRedirectScanner(BaseScanner):
    module_name = "redirect"
    description = "Open redirect detection"

    def __init__(self) -> None:
        super().__init__()
        self._payloads_data = self._load_payloads()

    def _load_payloads(self) -> dict:
        import pathlib

        path = pathlib.Path(__file__).parent.parent / "payloads" / "redirect.yaml"
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        params = endpoint.get("params", {})

        redirect_param_names = set(self._payloads_data.get("redirect_params", []))
        payloads = self._payloads_data.get("redirects", [])[:8]
        canary = self._payloads_data.get("canary_domain", "evil.com")

        # find parameters that look like redirect targets
        target_params = []
        for param_name in params:
            if param_name.lower() in redirect_param_names:
                target_params.append(param_name)

        # if no known redirect params, test all params
        if not target_params:
            target_params = list(params.keys())

        for param_name in target_params:
            for payload in payloads:
                injected = {**params, param_name: payload}

                # send request without following redirects
                try:
                    resp = await client.request(
                        method, url,
                        params=injected if method == "GET" else None,
                        data=injected if method != "GET" else None,
                        follow_redirects=False,
                    )
                except Exception:
                    continue

                # check if the response is a redirect to our evil domain
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if canary in location:
                        results.append(ScanResult(
                            module=self.module_name,
                            severity="medium",
                            title=f"Open redirect in parameter '{param_name}'",
                            description=(
                                f"The parameter '{param_name}' allows redirection to "
                                f"an external domain. The server redirected to: {location}"
                            ),
                            evidence=f"Location: {location}",
                            request_data=self._format_request(method, url, params=injected),
                            response_data=f"HTTP {resp.status_code}\nLocation: {location}",
                            remediation=REMEDIATION,
                            soc2_criteria=SOC2,
                        ))
                        break  # one finding per parameter

                # also check for redirect in response body (meta refresh, JS redirect)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if canary in body and (
                        "meta http-equiv" in body
                        or "window.location" in body
                        or "document.location" in body
                    ):
                        results.append(ScanResult(
                            module=self.module_name,
                            severity="medium",
                            title=f"Open redirect (client-side) in parameter '{param_name}'",
                            description=(
                                f"The parameter '{param_name}' triggers a client-side "
                                f"redirect to an external domain via meta refresh or JavaScript."
                            ),
                            evidence=f"Canary domain '{canary}' found in response body",
                            request_data=self._format_request(method, url, params=injected),
                            response_data=self._format_response(resp),
                            remediation=REMEDIATION,
                            soc2_criteria=SOC2,
                        ))
                        break

        return results
