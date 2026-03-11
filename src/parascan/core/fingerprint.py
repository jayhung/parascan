"""target tech stack detection from headers and response patterns."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger("parascan.fingerprint")

HEADER_SIGNATURES: dict[str, str] = {
    "X-Powered-By": "framework",
    "Server": "server",
    "X-AspNet-Version": "asp.net",
    "X-Generator": "generator",
    "X-Drupal-Cache": "drupal",
    "X-WordPress": "wordpress",
}

BODY_SIGNATURES: list[tuple[str, str]] = [
    ("wp-content", "WordPress"),
    ("drupal", "Drupal"),
    ("laravel", "Laravel"),
    ("django", "Django"),
    ("express", "Express.js"),
    ("next.js", "Next.js"),
    ("nuxt", "Nuxt.js"),
    ("rails", "Ruby on Rails"),
    ("spring", "Spring"),
    ("graphql", "GraphQL"),
    ("__VIEWSTATE", "ASP.NET"),
]

# WAF detection: header key → WAF name
WAF_HEADER_SIGNATURES: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-cdn": "CDN",
    "x-aws-waf": "AWS WAF",
}

# WAF detection by server header value
WAF_SERVER_SIGNATURES: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "akamaighost": "Akamai",
    "amazons3": "AWS S3",
}


async def fingerprint_target(
    client: httpx.AsyncClient,
    url: str,
    scan_id: int | None = None,
) -> dict[str, list[str]]:
    """detect tech stack, server info, and WAF from the target."""
    from parascan.core.state import save_scan_event

    async def _event(level: str, msg: str, detail: str | None = None) -> None:
        if scan_id is not None:
            await save_scan_event(scan_id, level, "fingerprint", msg, detail)

    result: dict[str, list[str]] = {
        "server": [],
        "frameworks": [],
        "waf": [],
        "technologies": [],
    }

    try:
        resp = await client.get(url, follow_redirects=True)
    except Exception as e:
        logger.warning("fingerprint request failed for %s: %s", url, e)
        await _event("error", f"fingerprint request failed: {e}")
        return result

    logger.info("fingerprint got HTTP %d from %s", resp.status_code, url)

    # check response headers
    for header, category in HEADER_SIGNATURES.items():
        value = resp.headers.get(header)
        if value:
            result["technologies"].append(f"{header}: {value}")
            if category == "server":
                result["server"].append(value)
            else:
                result["frameworks"].append(value)

    # detect WAF by presence of known headers
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for header_key, name in WAF_HEADER_SIGNATURES.items():
        if header_key in headers_lower:
            result["waf"].append(name)

    # detect WAF/CDN by server header value
    server_val = headers_lower.get("server", "").lower()
    for sig, name in WAF_SERVER_SIGNATURES.items():
        if sig in server_val and name not in result["waf"]:
            result["waf"].append(name)

    # check body patterns (works even on non-200 responses)
    try:
        body = resp.text.lower()
    except Exception:
        body = ""
    for pattern, tech in BODY_SIGNATURES:
        if pattern.lower() in body:
            if tech not in result["technologies"]:
                result["technologies"].append(tech)

    fp_str = format_fingerprint(result)
    if fp_str != "No fingerprint data detected":
        await _event("info", f"detected: {fp_str}")
    else:
        await _event("warning", "no fingerprint data detected", f"HTTP {resp.status_code}")

    return result


def format_fingerprint(data: dict[str, list[str]]) -> str:
    """format fingerprint data as a readable string."""
    lines = []
    if data.get("server"):
        lines.append(f"Server: {', '.join(data['server'])}")
    if data.get("frameworks"):
        lines.append(f"Frameworks: {', '.join(data['frameworks'])}")
    if data.get("waf"):
        lines.append(f"WAF: {', '.join(data['waf'])}")
    if data.get("technologies"):
        lines.append(f"Technologies: {', '.join(data['technologies'])}")
    return "\n".join(lines) if lines else "No fingerprint data detected"
