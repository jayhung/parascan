"""TLS/SSL scanner — checks protocol versions, cipher suites, and certificate validity."""

from __future__ import annotations

import datetime
import ssl
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

from parascan.scanners.base import BaseScanner, ScanResult


# weak protocol versions that should be flagged
WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}

# weak cipher suite keywords
WEAK_CIPHER_KEYWORDS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "RC2",
]

REMEDIATION_PROTOCOL = (
    "Disable TLS 1.0 and TLS 1.1 on your server. Only allow TLS 1.2 and TLS 1.3. "
    "For nginx: 'ssl_protocols TLSv1.2 TLSv1.3;'. For Apache: "
    "'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'. On Heroku/cloud platforms, "
    "check your load balancer or CDN TLS settings."
)

REMEDIATION_CIPHER = (
    "Disable weak cipher suites and prefer modern ciphers. For nginx: "
    "'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...;'. "
    "Use Mozilla SSL Configuration Generator (https://ssl-config.mozilla.org/) "
    "to generate a secure configuration for your server."
)

REMEDIATION_CERT_EXPIRY = (
    "Renew your TLS certificate before it expires. Set up automated renewal "
    "with Let's Encrypt / certbot or your certificate provider. Configure "
    "monitoring alerts for certificate expiry (e.g., 30 days before)."
)

REMEDIATION_SELF_SIGNED = (
    "Replace self-signed certificates with certificates issued by a trusted "
    "Certificate Authority (CA). Use Let's Encrypt for free, trusted certificates. "
    "Self-signed certificates break the chain of trust and are rejected by browsers."
)

REMEDIATION_HSTS = (
    "Add the Strict-Transport-Security header with a long max-age and submit "
    "your domain to the HSTS preload list at https://hstspreload.org/. Required "
    "header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
)

SOC2 = "CC6.7"


class TLSScanner(BaseScanner):
    module_name = "tls"
    description = "TLS/SSL protocol, cipher suite, and certificate checks"

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]
        parsed = urlparse(url)

        if parsed.scheme != "https":
            return results

        host = parsed.hostname
        port = parsed.port or 443

        if not host:
            return results

        # run TLS checks synchronously (ssl module is not async)
        try:
            cert_info, protocol, cipher = _get_tls_info(host, port)
        except Exception as e:
            return results

        # check protocol version
        if protocol and protocol in WEAK_PROTOCOLS:
            results.append(ScanResult(
                module=self.module_name,
                severity="high",
                title=f"Weak TLS protocol: {protocol}",
                description=(
                    f"The server supports {protocol}, which is deprecated and has "
                    f"known vulnerabilities. Modern standards require TLS 1.2 or higher."
                ),
                evidence=f"Negotiated protocol: {protocol}",
                request_data=f"TLS handshake to {host}:{port}",
                remediation=REMEDIATION_PROTOCOL,
                soc2_criteria=SOC2,
            ))

        # check cipher suite
        if cipher:
            cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
            for weak in WEAK_CIPHER_KEYWORDS:
                if weak.lower() in cipher_name.lower():
                    results.append(ScanResult(
                        module=self.module_name,
                        severity="medium",
                        title=f"Weak cipher suite: {cipher_name}",
                        description=(
                            f"The server negotiated a cipher suite containing '{weak}', "
                            f"which is considered weak or deprecated."
                        ),
                        evidence=f"Cipher: {cipher_name}",
                        request_data=f"TLS handshake to {host}:{port}",
                        remediation=REMEDIATION_CIPHER,
                        soc2_criteria=SOC2,
                    ))
                    break

        # check certificate
        if cert_info:
            # check expiry
            not_after = cert_info.get("notAfter")
            if not_after:
                try:
                    expiry = _parse_cert_date(not_after)
                    now = datetime.datetime.now(datetime.UTC)
                    days_left = (expiry - now).days

                    if days_left < 0:
                        results.append(ScanResult(
                            module=self.module_name,
                            severity="critical",
                            title="TLS certificate expired",
                            description=(
                                f"The TLS certificate expired {abs(days_left)} day(s) ago "
                                f"on {not_after}."
                            ),
                            evidence=f"Certificate notAfter: {not_after}",
                            request_data=f"TLS handshake to {host}:{port}",
                            remediation=REMEDIATION_CERT_EXPIRY,
                            soc2_criteria=SOC2,
                        ))
                    elif days_left < 30:
                        results.append(ScanResult(
                            module=self.module_name,
                            severity="medium",
                            title=f"TLS certificate expiring in {days_left} days",
                            description=(
                                f"The TLS certificate expires on {not_after} "
                                f"({days_left} days remaining)."
                            ),
                            evidence=f"Certificate notAfter: {not_after}",
                            request_data=f"TLS handshake to {host}:{port}",
                            remediation=REMEDIATION_CERT_EXPIRY,
                            soc2_criteria=SOC2,
                        ))
                except Exception:
                    pass

            # check self-signed
            issuer = cert_info.get("issuer", ())
            subject = cert_info.get("subject", ())
            if issuer and subject and issuer == subject:
                results.append(ScanResult(
                    module=self.module_name,
                    severity="high",
                    title="Self-signed TLS certificate",
                    description=(
                        "The TLS certificate is self-signed (issuer matches subject). "
                        "This breaks the chain of trust."
                    ),
                    evidence=f"Issuer == Subject: {_format_cert_name(issuer)}",
                    request_data=f"TLS handshake to {host}:{port}",
                    remediation=REMEDIATION_SELF_SIGNED,
                    soc2_criteria=SOC2,
                ))

        # check HSTS preload readiness
        resp = await self._request(client, "GET", url)
        if resp:
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if hsts:
                if "preload" not in hsts.lower():
                    results.append(ScanResult(
                        module=self.module_name,
                        severity="info",
                        title="HSTS missing preload directive",
                        description=(
                            "The HSTS header is set but does not include the 'preload' "
                            "directive. Consider adding it and submitting to the preload list."
                        ),
                        evidence=f"Strict-Transport-Security: {hsts}",
                        request_data=self._format_request("GET", url),
                        remediation=REMEDIATION_HSTS,
                        soc2_criteria=SOC2,
                    ))

        return results


def _get_tls_info(host: str, port: int) -> tuple[dict, str, tuple]:
    """connect to host and extract TLS certificate, protocol, and cipher info."""
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            protocol = ssock.version()
            cipher = ssock.cipher()
            return cert or {}, protocol or "", cipher or ()


def _parse_cert_date(date_str: str) -> datetime.datetime:
    """parse certificate date string to datetime."""
    # format: 'Sep 25 00:00:00 2025 GMT'
    return datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=datetime.UTC
    )


def _format_cert_name(name_tuple: tuple) -> str:
    """format certificate subject/issuer tuple to readable string."""
    parts = []
    for rdn in name_tuple:
        for attr_type, value in rdn:
            parts.append(f"{attr_type}={value}")
    return ", ".join(parts)
