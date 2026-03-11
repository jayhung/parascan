"""information disclosure scanner — detects debug endpoints, stack traces, and version leaks."""

from __future__ import annotations

import pathlib
from typing import Any

import httpx
import yaml

from parascan.core.soft404 import Soft404Detector
from parascan.scanners.base import BaseScanner, ScanResult


REMEDIATION_DEBUG = (
    "Remove or restrict access to debug and administrative endpoints in production. "
    "Ensure .env files, .git directories, and configuration files are not served "
    "by your web server. Add rules to your web server config to deny access to "
    "sensitive paths (e.g., 'location ~ /\\. { deny all; }' in nginx)."
)

REMEDIATION_STACKTRACE = (
    "Disable detailed error messages in production. Configure your framework to "
    "return generic error pages without stack traces. In Django: set DEBUG=False. "
    "In Express: use a custom error handler. In Rails: set config.consider_all_requests_local=false."
)

REMEDIATION_VERSION = (
    "Remove or suppress server version headers in production. Configure your web "
    "server to omit the Server, X-Powered-By, and framework-specific version headers. "
    "For nginx: 'server_tokens off;'. For Express: 'app.disable(\"x-powered-by\")'."
)

REMEDIATION_SOURCEMAP = (
    "Do not deploy JavaScript source maps to production. Remove .map files from "
    "your production build or restrict access to them. Source maps expose original "
    "source code, making it easier for attackers to find vulnerabilities."
)

SOC2 = "CC7.1"

# sensitive paths to probe
SENSITIVE_PATHS = [
    ("/.env", "Environment configuration file"),
    ("/.git/config", "Git repository configuration"),
    ("/.git/HEAD", "Git repository HEAD reference"),
    ("/server-status", "Apache server status page"),
    ("/server-info", "Apache server info page"),
    ("/.htaccess", "Apache access configuration"),
    ("/.htpasswd", "Apache password file"),
    ("/phpinfo.php", "PHP info page"),
    ("/debug", "Debug endpoint"),
    ("/debug/default/view", "Yii debug panel"),
    ("/_debug", "Debug endpoint"),
    ("/actuator", "Spring Boot actuator"),
    ("/actuator/env", "Spring Boot environment"),
    ("/actuator/health", "Spring Boot health"),
    ("/elmah.axd", ".NET error log"),
    ("/trace", "Spring Boot trace"),
    ("/swagger.json", "Swagger/OpenAPI spec"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/api-docs", "API documentation"),
    ("/graphql", "GraphQL endpoint"),
    ("/wp-config.php.bak", "WordPress config backup"),
    ("/web.config", "IIS configuration"),
    ("/.DS_Store", "macOS directory metadata"),
    ("/crossdomain.xml", "Flash cross-domain policy"),
]

# signatures that indicate exposed sensitive data
SENSITIVE_SIGNATURES = {
    "/.env": ["DB_PASSWORD", "DATABASE_URL", "SECRET_KEY", "AWS_", "API_KEY"],
    "/.git/config": ["[core]", "[remote", "repositoryformatversion"],
    "/.git/HEAD": ["ref: refs/"],
    "/phpinfo.php": ["phpinfo()", "PHP Version", "php.ini"],
    "/actuator": ['"status"', '"_links"'],
    "/actuator/env": ['"propertySources"', '"activeProfiles"'],
    "/swagger.json": ['"swagger"', '"openapi"', '"paths"'],
}

# patterns indicating stack traces
STACKTRACE_PATTERNS = [
    "Traceback (most recent call last)",
    "at java.",
    "at org.",
    "at com.",
    "NullPointerException",
    "RuntimeException",
    "Exception in thread",
    "Fatal error:",
    "Parse error:",
    "SyntaxError:",
    "TypeError:",
    "ReferenceError:",
    "SQLSTATE[",
    "pg_query()",
    "mysql_",
    "Microsoft OLE DB",
    "Unhandled Exception",
    "Stack Trace:",
    "System.NullReferenceException",
]


class InfoDisclosureScanner(BaseScanner):
    module_name = "info-disclosure"
    description = "Debug endpoints, stack traces, version headers, and source maps"

    def __init__(self) -> None:
        super().__init__()
        self.soft404: Soft404Detector | None = None

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

        # probe sensitive paths
        for path, desc in SENSITIVE_PATHS:
            probe_url = base_url + path
            resp = await self._request(client, "GET", probe_url)
            if resp is None or resp.status_code != 200:
                continue

            # check for sensitive content signatures
            sigs = SENSITIVE_SIGNATURES.get(path, [])
            body = resp.text
            matched_sig = None
            for sig in sigs:
                if sig in body:
                    matched_sig = sig
                    break

            if matched_sig:
                results.append(ScanResult(
                    module=self.module_name,
                    severity="high" if path in ("/.env", "/.git/config", "/actuator/env") else "medium",
                    title=f"Sensitive file exposed: {path}",
                    description=(
                        f"{desc} is accessible at {probe_url}. "
                        f"This may expose credentials, configuration, or internal details."
                    ),
                    evidence=f"Signature found: {matched_sig}",
                    request_data=self._format_request("GET", probe_url),
                    response_data=self._format_response(resp),
                    remediation=REMEDIATION_DEBUG,
                    soc2_criteria=SOC2,
                ))
            elif len(body) > 50 and path not in ("/robots.txt", "/crossdomain.xml"):
                # skip if the response matches the soft-404 baseline (SPA catch-all)
                if self.soft404 and self.soft404.is_soft_404(resp):
                    continue
                # non-empty response on sensitive path without specific sig
                if path in ("/.env", "/.git/config", "/.git/HEAD", "/.htpasswd"):
                    results.append(ScanResult(
                        module=self.module_name,
                        severity="medium",
                        title=f"Potentially sensitive file at {path}",
                        description=(
                            f"{desc} returned content ({len(body)} bytes). "
                            f"Review whether this should be publicly accessible."
                        ),
                        evidence=f"Response size: {len(body)} bytes",
                        request_data=self._format_request("GET", probe_url),
                        response_data=self._format_response(resp),
                        remediation=REMEDIATION_DEBUG,
                        soc2_criteria=SOC2,
                    ))

        # check for stack traces in error responses
        error_triggers = [
            ({"_invalid": "%%%"}, "malformed parameter"),
            ({"id": "'" * 50}, "long quote string"),
        ]

        for trigger_params, trigger_desc in error_triggers:
            resp = await self._request(client, "GET", url, params=trigger_params)
            if resp is None:
                continue

            body = resp.text
            for pattern in STACKTRACE_PATTERNS:
                if pattern.lower() in body.lower():
                    results.append(ScanResult(
                        module=self.module_name,
                        severity="medium",
                        title=f"Stack trace in error response",
                        description=(
                            f"Sending a {trigger_desc} caused the server to return "
                            f"a stack trace or detailed error message. This can reveal "
                            f"internal code structure and library versions to attackers."
                        ),
                        evidence=f"Pattern found: {pattern}",
                        request_data=self._format_request("GET", url, params=trigger_params),
                        response_data=self._format_response(resp),
                        remediation=REMEDIATION_STACKTRACE,
                        soc2_criteria=SOC2,
                    ))
                    break
            else:
                continue
            break  # found a stack trace, no need for more triggers

        # check for source maps
        resp = await self._request(client, "GET", url)
        if resp and resp.status_code == 200:
            # check for SourceMappingURL in JS responses
            sm_header = resp.headers.get("SourceMap") or resp.headers.get("X-SourceMap")
            if sm_header:
                results.append(ScanResult(
                    module=self.module_name,
                    severity="low",
                    title="Source map header exposed",
                    description=(
                        f"The server exposes a SourceMap header pointing to: {sm_header}. "
                        f"Source maps reveal original source code."
                    ),
                    evidence=f"SourceMap: {sm_header}",
                    request_data=self._format_request("GET", url),
                    remediation=REMEDIATION_SOURCEMAP,
                    soc2_criteria=SOC2,
                ))

        return results
