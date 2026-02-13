"""security headers and CORS misconfiguration scanner."""

from __future__ import annotations

from typing import Any

import httpx

from parascan.scanners.base import BaseScanner, ScanResult


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HSTS header is missing. The site does not enforce HTTPS connections.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "CSP header is missing. The site has no protection against XSS and data injection attacks.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options header is missing. Browser may MIME-sniff responses.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options header is missing. The site may be vulnerable to clickjacking.",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "X-XSS-Protection header is missing (legacy, but still useful for older browsers).",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy header is missing. Referrer information may leak to third parties.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy header is missing. Browser features are not restricted.",
    },
}


class SecurityHeadersScanner(BaseScanner):
    module_name = "headers"
    description = "Security headers and CORS misconfiguration checks"

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]

        resp = await self._request(client, "GET", url)
        if resp is None:
            return results

        # check missing security headers
        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in {k.lower() for k in resp.headers}:
                results.append(ScanResult(
                    module=self.module_name,
                    severity=info["severity"],
                    title=f"Missing security header: {header}",
                    description=info["description"],
                    evidence=f"Header '{header}' not found in response",
                    request_data=self._format_request("GET", url),
                    response_data=self._format_response(resp),
                ))

        # check CORS misconfiguration
        cors_result = await self._check_cors(client, url)
        if cors_result:
            results.append(cors_result)

        # check for information disclosure headers
        info_results = self._check_info_disclosure(resp)
        results.extend(info_results)

        return results

    async def _check_cors(
        self, client: httpx.AsyncClient, url: str
    ) -> ScanResult | None:
        """check for overly permissive CORS configuration."""
        evil_origin = "https://evil.com"
        resp = await self._request(
            client, "GET", url, headers={"Origin": evil_origin}
        )
        if resp is None:
            return None

        acao = resp.headers.get("Access-Control-Allow-Origin", "")

        if acao == "*":
            return ScanResult(
                module=self.module_name,
                severity="medium",
                title="CORS: wildcard Access-Control-Allow-Origin",
                description=(
                    "The server returns 'Access-Control-Allow-Origin: *', allowing "
                    "any website to make cross-origin requests."
                ),
                evidence="Access-Control-Allow-Origin: *",
                request_data=self._format_request("GET", url, headers={"Origin": evil_origin}),
                response_data=self._format_response(resp),
            )

        if evil_origin in acao:
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            severity = "high" if acac.lower() == "true" else "medium"
            return ScanResult(
                module=self.module_name,
                severity=severity,
                title="CORS: origin reflection vulnerability",
                description=(
                    f"The server reflects the Origin header in Access-Control-Allow-Origin. "
                    f"An attacker's domain '{evil_origin}' was accepted."
                    + (" Credentials are also allowed." if acac.lower() == "true" else "")
                ),
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                request_data=self._format_request("GET", url, headers={"Origin": evil_origin}),
                response_data=self._format_response(resp),
            )

        return None

    def _check_info_disclosure(self, resp: httpx.Response) -> list[ScanResult]:
        """check for headers that leak server info."""
        results: list[ScanResult] = []
        disclosure_headers = {
            "Server": "Server software version disclosed",
            "X-Powered-By": "Backend framework disclosed",
            "X-AspNet-Version": "ASP.NET version disclosed",
            "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
        }

        for header, desc in disclosure_headers.items():
            value = resp.headers.get(header)
            if value:
                results.append(ScanResult(
                    module=self.module_name,
                    severity="info",
                    title=f"Information disclosure: {header}",
                    description=f"{desc}: {value}",
                    evidence=f"{header}: {value}",
                ))

        return results
