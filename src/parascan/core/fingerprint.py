"""target tech stack detection from headers and response patterns."""

from __future__ import annotations

import httpx


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

WAF_SIGNATURES: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-cdn": "CDN",
    "server: AkamaiGHost": "Akamai",
    "x-aws-waf": "AWS WAF",
}


async def fingerprint_target(client: httpx.AsyncClient, url: str) -> dict[str, list[str]]:
    """detect tech stack, server info, and WAF from the target."""
    result: dict[str, list[str]] = {
        "server": [],
        "frameworks": [],
        "waf": [],
        "technologies": [],
    }

    try:
        resp = await client.get(url, follow_redirects=True)
    except Exception:
        return result

    # check response headers
    for header, category in HEADER_SIGNATURES.items():
        value = resp.headers.get(header)
        if value:
            result["technologies"].append(f"{header}: {value}")
            if category == "server":
                result["server"].append(value)
            else:
                result["frameworks"].append(value)

    # check WAF headers
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for sig, name in WAF_SIGNATURES.items():
        if sig.lower() in headers_lower:
            result["waf"].append(name)

    # check body patterns
    body = resp.text.lower()
    for pattern, tech in BODY_SIGNATURES:
        if pattern.lower() in body:
            if tech not in result["technologies"]:
                result["technologies"].append(tech)

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
