"""SQL injection scanner — error-based, boolean-blind, time-blind detection."""

from __future__ import annotations

import time
from typing import Any

import httpx
import yaml

from parascan.scanners.base import BaseScanner, ScanResult


REMEDIATION = (
    "Use parameterized queries (prepared statements) for all database operations. "
    "Never concatenate user input into SQL strings. Use your framework's ORM or "
    "query builder (e.g., SQLAlchemy, Django ORM, Prisma). Apply input validation "
    "and restrict database user privileges to the minimum required."
)

SOC2 = "CC6.8"


class SQLInjectionScanner(BaseScanner):
    module_name = "sqli"
    description = "SQL injection detection (error-based, blind, time-based)"

    def __init__(self) -> None:
        super().__init__()
        self._payloads_data = self._load_sqli_payloads()

    def _load_sqli_payloads(self) -> dict:
        import pathlib

        path = pathlib.Path(__file__).parent.parent / "payloads" / "sqli.yaml"
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
            # try error-based on the URL itself with a query param
            params = {"id": "1"}

        error_sigs = self._payloads_data.get("error_signatures", [])

        # error-based detection
        for payload in self._payloads_data.get("error_based", [])[:8]:
            result = await self._test_error_based(
                client, url, method, params, payload, error_sigs
            )
            if result:
                results.append(result)
                break  # one finding per type is enough

        # boolean-blind detection
        blind_result = await self._test_boolean_blind(client, url, method, params)
        if blind_result:
            results.append(blind_result)

        # time-blind detection
        time_result = await self._test_time_blind(client, url, method, params)
        if time_result:
            results.append(time_result)

        return results

    async def _test_error_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        params: dict,
        payload: str,
        error_sigs: list[str],
    ) -> ScanResult | None:
        """inject payload and check for SQL error messages in response."""
        for param_name in params:
            injected = {**params, param_name: payload}

            if method == "GET":
                resp = await self._request(client, method, url, params=injected)
            else:
                resp = await self._request(client, method, url, data=injected)

            if resp is None:
                continue

            body = resp.text.lower()
            for sig in error_sigs:
                if sig.lower() in body:
                    return ScanResult(
                        module=self.module_name,
                        severity="high",
                        title=f"SQL injection (error-based) in parameter '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' appears vulnerable to SQL injection. "
                            f"The payload '{payload}' triggered an SQL error signature: '{sig}'."
                        ),
                        evidence=f"Error signature found: {sig}",
                        request_data=self._format_request(method, url, params=injected),
                        response_data=self._format_response(resp),
                        remediation=REMEDIATION,
                        soc2_criteria=SOC2,
                    )
        return None

    async def _test_boolean_blind(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        params: dict,
    ) -> ScanResult | None:
        """detect boolean-blind SQLi by comparing true/false responses."""
        blind_payloads = self._payloads_data.get("boolean_blind", [])
        if len(blind_payloads) < 2:
            return None

        for param_name in params:
            # true condition
            true_payload = blind_payloads[0]  # ' AND '1'='1
            false_payload = blind_payloads[1]  # ' AND '1'='2

            true_params = {**params, param_name: f"{params[param_name]}{true_payload}"}
            false_params = {**params, param_name: f"{params[param_name]}{false_payload}"}

            if method == "GET":
                true_resp = await self._request(client, method, url, params=true_params)
                false_resp = await self._request(client, method, url, params=false_params)
            else:
                true_resp = await self._request(client, method, url, data=true_params)
                false_resp = await self._request(client, method, url, data=false_params)

            if true_resp is None or false_resp is None:
                continue

            # significant difference in response length suggests blind SQLi
            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            if true_len > 0 and abs(true_len - false_len) / max(true_len, 1) > 0.3:
                if true_resp.status_code == false_resp.status_code:
                    return ScanResult(
                        module=self.module_name,
                        severity="high",
                        title=f"SQL injection (boolean-blind) in parameter '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' may be vulnerable to boolean-blind "
                            f"SQL injection. True/false conditions produced significantly "
                            f"different response sizes ({true_len} vs {false_len} bytes)."
                        ),
                        evidence=f"True response: {true_len}B, False response: {false_len}B",
                        request_data=self._format_request(method, url, params=true_params),
                        response_data=self._format_response(true_resp),
                        remediation=REMEDIATION,
                        soc2_criteria=SOC2,
                    )
        return None

    async def _test_time_blind(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        params: dict,
    ) -> ScanResult | None:
        """detect time-blind SQLi by measuring response time with sleep payloads."""
        time_payloads = self._payloads_data.get("time_blind", [])

        for param_name in params:
            # get baseline response time
            baseline_start = time.monotonic()
            if method == "GET":
                await self._request(client, method, url, params=params)
            else:
                await self._request(client, method, url, data=params)
            baseline_time = time.monotonic() - baseline_start

            for payload in time_payloads[:3]:
                injected = {**params, param_name: f"{params[param_name]}{payload}"}

                start = time.monotonic()
                if method == "GET":
                    resp = await self._request(client, method, url, params=injected)
                else:
                    resp = await self._request(client, method, url, data=injected)
                elapsed = time.monotonic() - start

                if resp is None:
                    continue

                # if response took significantly longer than baseline, likely time-blind sqli
                if elapsed > baseline_time + 2.5:
                    return ScanResult(
                        module=self.module_name,
                        severity="high",
                        title=f"SQL injection (time-blind) in parameter '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' may be vulnerable to time-blind "
                            f"SQL injection. Payload '{payload}' caused a {elapsed:.1f}s "
                            f"delay (baseline: {baseline_time:.1f}s)."
                        ),
                        evidence=f"Response time: {elapsed:.1f}s (baseline: {baseline_time:.1f}s)",
                        request_data=self._format_request(method, url, params=injected),
                        response_data=self._format_response(resp),
                        remediation=REMEDIATION,
                        soc2_criteria=SOC2,
                    )
        return None
