"""command injection scanner — detects OS command injection vulnerabilities."""

from __future__ import annotations

import time
from typing import Any

import httpx
import yaml

from parascan.scanners.base import BaseScanner, ScanResult


class CommandInjectionScanner(BaseScanner):
    module_name = "cmdi"
    description = "OS command injection detection"

    def __init__(self) -> None:
        super().__init__()
        self._payloads_data = self._load_payloads()

    def _load_payloads(self) -> dict:
        import pathlib

        path = pathlib.Path(__file__).parent.parent / "payloads" / "cmdi.yaml"
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
            params = {"cmd": "test", "input": "test"}

        success_sigs = self._payloads_data.get("success_signatures", [])

        # output-based detection
        for payload in self._payloads_data.get("output_based", [])[:6]:
            for param_name in params:
                injected = {**params, param_name: payload}

                if method == "GET":
                    resp = await self._request(client, method, url, params=injected)
                else:
                    resp = await self._request(client, method, url, data=injected)

                if resp is None:
                    continue

                body = resp.text
                for sig in success_sigs:
                    if sig in body:
                        results.append(ScanResult(
                            module=self.module_name,
                            severity="critical",
                            title=f"Command injection in parameter '{param_name}'",
                            description=(
                                f"The parameter '{param_name}' is vulnerable to OS command "
                                f"injection. The payload '{payload}' caused command output "
                                f"to appear in the response."
                            ),
                            evidence=f"Command output signature: {sig}",
                            request_data=self._format_request(method, url, params=injected),
                            response_data=self._format_response(resp),
                        ))
                        return results  # critical finding, stop

        # time-based detection
        for payload in self._payloads_data.get("time_based", [])[:3]:
            for param_name in params:
                injected = {**params, param_name: payload}

                start = time.monotonic()
                if method == "GET":
                    resp = await self._request(client, method, url, params=injected)
                else:
                    resp = await self._request(client, method, url, data=injected)
                elapsed = time.monotonic() - start

                if resp is None:
                    continue

                if elapsed > 2.5:
                    results.append(ScanResult(
                        module=self.module_name,
                        severity="critical",
                        title=f"Command injection (time-based) in parameter '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' may be vulnerable to OS command "
                            f"injection. The payload '{payload}' caused a {elapsed:.1f}s delay."
                        ),
                        evidence=f"Response time: {elapsed:.1f}s",
                        request_data=self._format_request(method, url, params=injected),
                        response_data=self._format_response(resp),
                    ))
                    return results

        return results
