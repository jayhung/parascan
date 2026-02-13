"""SSRF scanner — detects server-side request forgery vulnerabilities."""

from __future__ import annotations

from typing import Any

import httpx
import yaml

from parascan.scanners.base import BaseScanner, ScanResult


class SSRFScanner(BaseScanner):
    module_name = "ssrf"
    description = "Server-side request forgery detection"

    def __init__(self) -> None:
        super().__init__()
        self._payloads_data = self._load_payloads()

    def _load_payloads(self) -> dict:
        import pathlib

        path = pathlib.Path(__file__).parent.parent / "payloads" / "ssrf.yaml"
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

        if not params:
            params = {"url": "https://example.com", "link": "https://example.com"}

        # only test params that look like they could take URLs
        url_param_names = {"url", "link", "href", "src", "uri", "path", "redirect",
                          "callback", "next", "dest", "fetch", "load", "page", "file"}

        success_sigs = self._payloads_data.get("success_signatures", [])

        # get baseline response for comparison
        if method == "GET":
            baseline = await self._request(client, method, url, params=params)
        else:
            baseline = await self._request(client, method, url, data=params)
        baseline_len = len(baseline.text) if baseline else 0

        for param_name in params:
            # prioritize params with URL-like names
            is_url_param = param_name.lower() in url_param_names

            payloads = []
            if is_url_param:
                payloads.extend(self._payloads_data.get("cloud_metadata", [])[:3])
                payloads.extend(self._payloads_data.get("internal_urls", [])[:3])
            else:
                payloads.extend(self._payloads_data.get("cloud_metadata", [])[:2])

            for payload in payloads:
                injected = {**params, param_name: payload}

                if method == "GET":
                    resp = await self._request(client, method, url, params=injected)
                else:
                    resp = await self._request(client, method, url, data=injected)

                if resp is None:
                    continue

                # check for SSRF signatures in response
                body = resp.text.lower()
                for sig in success_sigs:
                    if sig.lower() in body:
                        results.append(ScanResult(
                            module=self.module_name,
                            severity="critical",
                            title=f"SSRF detected in parameter '{param_name}'",
                            description=(
                                f"The parameter '{param_name}' is vulnerable to SSRF. "
                                f"The payload '{payload}' caused the server to make an "
                                f"internal request, returning sensitive data."
                            ),
                            evidence=f"SSRF signature found: {sig}",
                            request_data=self._format_request(method, url, params=injected),
                            response_data=self._format_response(resp),
                        ))
                        break

                # check for significant response size change (may indicate fetched content)
                resp_len = len(resp.text)
                if baseline_len > 0 and resp_len > baseline_len * 2 and resp_len > 500:
                    if not any(r.title.endswith(f"'{param_name}'") for r in results):
                        results.append(ScanResult(
                            module=self.module_name,
                            severity="medium",
                            title=f"Potential SSRF in parameter '{param_name}'",
                            description=(
                                f"The parameter '{param_name}' may be vulnerable to SSRF. "
                                f"The payload '{payload}' caused a significantly larger "
                                f"response ({resp_len}B vs baseline {baseline_len}B)."
                            ),
                            evidence=f"Response size: {resp_len}B (baseline: {baseline_len}B)",
                            request_data=self._format_request(method, url, params=injected),
                            response_data=self._format_response(resp),
                        ))

            if results:
                break  # found SSRF in this param, stop

        return results
