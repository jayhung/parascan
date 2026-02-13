"""XXE scanner — detects XML external entity injection vulnerabilities."""

from __future__ import annotations

from typing import Any

import httpx
import yaml

from parascan.scanners.base import BaseScanner, ScanResult


class XXEScanner(BaseScanner):
    module_name = "xxe"
    description = "XML external entity injection detection"

    def __init__(self) -> None:
        super().__init__()
        self._payloads_data = self._load_payloads()

    def _load_payloads(self) -> dict:
        import pathlib

        path = pathlib.Path(__file__).parent.parent / "payloads" / "xxe.yaml"
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

        # XXE only applies to endpoints that accept XML
        if method not in ("POST", "PUT", "PATCH"):
            return results

        success_sigs = self._payloads_data.get("success_signatures", [])

        # first check if the endpoint accepts XML
        test_xml = '<?xml version="1.0"?><root>test</root>'
        resp = await self._request(
            client, method, url,
            content=test_xml,
            headers={"Content-Type": "application/xml"},
        )

        # if the server errors on XML, it likely doesn't accept it
        if resp is None or resp.status_code in (415, 400):
            return results

        # test basic XXE payloads
        for payload in self._payloads_data.get("basic", []):
            resp = await self._request(
                client, method, url,
                content=payload.strip(),
                headers={"Content-Type": "application/xml"},
            )

            if resp is None:
                continue

            body = resp.text
            for sig in success_sigs:
                if sig in body:
                    results.append(ScanResult(
                        module=self.module_name,
                        severity="critical",
                        title=f"XXE injection at {url}",
                        description=(
                            f"The endpoint accepts XML with external entity references. "
                            f"An attacker can read arbitrary files from the server."
                        ),
                        evidence=f"XXE signature found: {sig}",
                        request_data=self._format_request(
                            method, url,
                            headers={"Content-Type": "application/xml"},
                        ),
                        response_data=self._format_response(resp),
                    ))
                    return results  # critical, stop

        # test SSRF via XXE
        for payload in self._payloads_data.get("ssrf_via_xxe", []):
            resp = await self._request(
                client, method, url,
                content=payload.strip(),
                headers={"Content-Type": "application/xml"},
            )

            if resp is None:
                continue

            body = resp.text
            for sig in success_sigs:
                if sig in body:
                    results.append(ScanResult(
                        module=self.module_name,
                        severity="critical",
                        title=f"XXE-based SSRF at {url}",
                        description=(
                            f"The endpoint is vulnerable to XXE-based SSRF. "
                            f"An attacker can make the server fetch internal resources."
                        ),
                        evidence=f"SSRF via XXE signature: {sig}",
                        request_data=self._format_request(
                            method, url,
                            headers={"Content-Type": "application/xml"},
                        ),
                        response_data=self._format_response(resp),
                    ))
                    return results

        return results
