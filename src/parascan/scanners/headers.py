"""security headers and CORS misconfiguration scanner."""

from __future__ import annotations

from typing import Any

import httpx

from parascan.scanners.base import BaseScanner, ScanResult


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HSTS header is missing. The site does not enforce HTTPS connections.",
        "remediation": (
            "Add the Strict-Transport-Security header to all responses: "
            "'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'. "
            "Ensure all resources are served over HTTPS before enabling."
        ),
        "soc2": "CC6.7",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "CSP header is missing. The site has no protection against XSS and data injection attacks.",
        "remediation": (
            "Add a Content-Security-Policy header. Start with a report-only policy to "
            "identify violations: \"Content-Security-Policy-Report-Only: default-src 'self'\". "
            "Then tighten the policy to restrict script sources and disable inline scripts."
        ),
        "soc2": "CC6.8",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options header is missing. Browser may MIME-sniff responses.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' to all responses.",
        "soc2": "CC7.1",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options header is missing. The site may be vulnerable to clickjacking.",
        "remediation": (
            "Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN' if framing from the same origin "
            "is needed). Also set 'frame-ancestors' in your Content-Security-Policy."
        ),
        "soc2": "CC6.8",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy header is missing. Referrer information may leak to third parties.",
        "remediation": (
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' or "
            "'Referrer-Policy: no-referrer' to prevent leaking URL paths to third parties."
        ),
        "soc2": "CC7.1",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy header is missing. Browser features are not restricted.",
        "remediation": (
            "Add a Permissions-Policy header to restrict unnecessary browser features: "
            "'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
        ),
        "soc2": "CC7.1",
    },
}

CORS_REMEDIATION = (
    "Restrict Access-Control-Allow-Origin to specific trusted domains instead of "
    "using '*' or reflecting the Origin header. Never combine wildcard or reflected "
    "origins with Access-Control-Allow-Credentials: true. Validate origins against "
    "an explicit allowlist on the server."
)

INFO_REMEDIATION = (
    "Remove or suppress server version headers in production. Configure your web "
    "server to omit the Server, X-Powered-By, and framework-specific version headers. "
    "For nginx: 'server_tokens off;'. For Express: 'app.disable(\"x-powered-by\")'."
)


class SecurityHeadersScanner(BaseScanner):
    module_name = "headers"
    description = "Security headers and CORS misconfiguration checks"

    def __init__(self) -> None:
        super().__init__()
        # track reported titles across endpoints to avoid duplicates
        self._reported: set[str] = set()

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
            title = f"Missing security header: {header}"
            if title in self._reported:
                continue
            if header.lower() not in {k.lower() for k in resp.headers}:
                self._reported.add(title)
                results.append(ScanResult(
                    module=self.module_name,
                    severity=info["severity"],
                    title=title,
                    description=info["description"],
                    evidence=f"Header '{header}' not found in response",
                    request_data=self._format_request("GET", url),
                    response_data=self._format_response(resp),
                    remediation=info.get("remediation"),
                    soc2_criteria=info.get("soc2"),
                ))

        # check CORS misconfiguration
        cors_result = await self._check_cors(client, url)
        if cors_result and cors_result.title not in self._reported:
            self._reported.add(cors_result.title)
            results.append(cors_result)

        # check for information disclosure headers
        for r in self._check_info_disclosure(resp):
            if r.title not in self._reported:
                self._reported.add(r.title)
                results.append(r)

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
                remediation=CORS_REMEDIATION,
                soc2_criteria="CC6.6",
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
                remediation=CORS_REMEDIATION,
                soc2_criteria="CC6.6",
            )

        return None

    def _check_info_disclosure(self, resp: httpx.Response) -> list[ScanResult]:
        """check for headers that leak server info or are deprecated."""
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
                    remediation=INFO_REMEDIATION,
                    soc2_criteria="CC7.1",
                ))

        # X-XSS-Protection is deprecated — flag its presence, not its absence
        xss_prot = resp.headers.get("X-XSS-Protection")
        if xss_prot is not None:
            results.append(ScanResult(
                module=self.module_name,
                severity="info",
                title="Deprecated header present: X-XSS-Protection",
                description=(
                    f"X-XSS-Protection is set to '{xss_prot}'. This header is deprecated "
                    f"and ignored by all modern browsers. Chrome removed its XSS Auditor "
                    f"in v78 (2019), and Firefox never implemented it. In some edge cases "
                    f"the auditor could be exploited to cause XSS via selective script blocking."
                ),
                evidence=f"X-XSS-Protection: {xss_prot}",
                remediation=(
                    "Remove the X-XSS-Protection header (or set it to '0') and rely on "
                    "a strong Content-Security-Policy instead. CSP provides comprehensive "
                    "XSS protection across all modern browsers."
                ),
                soc2_criteria="CC6.8",
            ))

        return results
