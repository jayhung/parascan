"""core scan engine — orchestrates discovery, scanning, and reporting."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import httpx
from rich.console import Console
from rich.table import Table

from parascan.core.auth import AuthManager
from parascan.core.config import TargetConfig
from parascan.core.db import ScanStatus, Severity
from parascan.core.fingerprint import fingerprint_target, format_fingerprint
from parascan.core.proxy import ProxyManager
from parascan.core.rate_limiter import RateLimiter
from parascan.core.scope import ScopeEnforcer
from parascan.core.state import (
    create_scan,
    finish_scan,
    get_latest_scan,
    get_unscanned_endpoints,
    mark_endpoint_scanned,
    save_endpoints,
    save_finding,
    update_scan_fingerprint,
    update_scan_progress,
)

if TYPE_CHECKING:
    from parascan.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger("parascan")
console = Console()


def _get_all_scanner_classes() -> list[type[BaseScanner]]:
    """import and return all available scanner classes."""
    from parascan.scanners.cmdi import CommandInjectionScanner
    from parascan.scanners.csrf import CSRFScanner
    from parascan.scanners.directory_traversal import DirectoryTraversalScanner
    from parascan.scanners.graphql.batch import GraphQLBatchScanner
    from parascan.scanners.graphql.injection import GraphQLInjectionScanner
    from parascan.scanners.graphql.introspection import GraphQLIntrospectionScanner
    from parascan.scanners.headers import SecurityHeadersScanner
    from parascan.scanners.idor import IDORScanner
    from parascan.scanners.jwt import JWTScanner
    from parascan.scanners.open_redirect import OpenRedirectScanner
    from parascan.scanners.sqli import SQLInjectionScanner
    from parascan.scanners.ssrf import SSRFScanner
    from parascan.scanners.xss import XSSScanner
    from parascan.scanners.xxe import XXEScanner

    return [
        SQLInjectionScanner,
        XSSScanner,
        SSRFScanner,
        CommandInjectionScanner,
        IDORScanner,
        SecurityHeadersScanner,
        DirectoryTraversalScanner,
        CSRFScanner,
        JWTScanner,
        XXEScanner,
        OpenRedirectScanner,
        GraphQLIntrospectionScanner,
        GraphQLInjectionScanner,
        GraphQLBatchScanner,
    ]


def _select_scanners(
    config: TargetConfig,
) -> list[type[BaseScanner]]:
    """select scanner classes based on config filters."""
    all_scanners = _get_all_scanner_classes()

    if config.scan.modules:
        all_scanners = [
            s for s in all_scanners if s.module_name in config.scan.modules
        ]

    if config.scan.exclude_modules:
        all_scanners = [
            s for s in all_scanners if s.module_name not in config.scan.exclude_modules
        ]

    return all_scanners


async def _discover_endpoints(
    client: httpx.AsyncClient,
    config: TargetConfig,
    scope: ScopeEnforcer,
) -> list[dict[str, Any]]:
    """discover endpoints via crawling, openapi import, or fallback."""
    endpoints: list[dict[str, Any]] = []

    if config.openapi:
        from parascan.discovery.openapi import parse_openapi_spec

        endpoints.extend(parse_openapi_spec(config.openapi, config.url))

    # always crawl the target for additional endpoints
    from parascan.discovery.crawler import crawl

    crawled = await crawl(client, config.url, scope, max_pages=50)
    for ep in crawled:
        if not any(e["url"] == ep["url"] and e["method"] == ep["method"] for e in endpoints):
            endpoints.append(ep)

    # if nothing found, at least scan the base url
    if not endpoints:
        endpoints.append({"url": config.url, "method": "GET", "params": {}})

    return endpoints


async def _run_scanner_on_endpoint(
    scanner: BaseScanner,
    client: httpx.AsyncClient,
    endpoint: dict[str, Any],
    rate_limiter: RateLimiter,
) -> list[ScanResult]:
    """run a single scanner against a single endpoint with rate limiting."""
    await rate_limiter.acquire()
    try:
        return await scanner.scan(client, endpoint)
    except Exception as e:
        logger.warning(f"scanner {scanner.module_name} failed on {endpoint['url']}: {e}")
        return []


async def run_scan(config: TargetConfig, resume: bool = False) -> int:
    """
    Execute a full scan against the target. Returns the scan id.

    If resume=True, picks up the most recent interrupted scan.
    """
    auth = AuthManager(config.auth)
    proxy = ProxyManager(config.proxy)
    scope = ScopeEnforcer(config.scope)
    rate_limiter = RateLimiter(config.scan.rate_limit)
    semaphore = asyncio.Semaphore(config.scan.concurrency)

    client_kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(30.0),
        "follow_redirects": True,
        "headers": auth.get_headers(),
    }
    cookies = auth.get_cookies()
    if cookies:
        client_kwargs["cookies"] = cookies
    client_kwargs.update(proxy.get_transport_kwargs())

    async with httpx.AsyncClient(**client_kwargs) as client:
        # handle resume
        if resume:
            latest = await get_latest_scan()
            if latest and latest.status == ScanStatus.INTERRUPTED.value:
                scan_id = latest.id
                console.print(f"[yellow]Resuming scan #{scan_id}[/yellow]")
                unscanned = await get_unscanned_endpoints(scan_id)
                ep_dicts = [
                    {"url": ep.url, "method": ep.method, "params": ep.params, "_id": ep.id}
                    for ep in unscanned
                ]
            else:
                console.print("[red]No interrupted scan found to resume.[/red]")
                return 0
        else:
            # create new scan
            scan_id = await create_scan(config.url)
            console.print(f"[bold green]Starting scan #{scan_id}[/bold green] → {config.url}")

            # fingerprint
            console.print("[dim]Fingerprinting target...[/dim]")
            fp_data = await fingerprint_target(client, config.url)
            fp_str = format_fingerprint(fp_data)
            await update_scan_fingerprint(scan_id, fp_str)
            if fp_str != "No fingerprint data detected":
                console.print(f"[cyan]{fp_str}[/cyan]")

            # discover endpoints
            console.print("[dim]Discovering endpoints...[/dim]")
            endpoints = await _discover_endpoints(client, config, scope)
            saved_ids = await save_endpoints(scan_id, endpoints)
            await update_scan_progress(scan_id, len(endpoints), 0)
            console.print(f"[green]Found {len(endpoints)} endpoint(s)[/green]")

            ep_dicts = []
            for ep, eid in zip(endpoints, saved_ids):
                ep["_id"] = eid
                ep_dicts.append(ep)

        # select scanners
        scanner_classes = _select_scanners(config)
        scanners = [cls() for cls in scanner_classes]
        console.print(
            f"[dim]Running {len(scanners)} scanner(s) against {len(ep_dicts)} endpoint(s)[/dim]"
        )

        # scan each endpoint
        total_findings = 0
        finding_counts: dict[str, int] = {}

        for i, ep in enumerate(ep_dicts):
            endpoint_id = ep.pop("_id", None)

            async def scan_endpoint(scanner: BaseScanner) -> list[ScanResult]:
                async with semaphore:
                    return await _run_scanner_on_endpoint(
                        scanner, client, ep, rate_limiter
                    )

            tasks = [scan_endpoint(s) for s in scanners]

            try:
                results_list = await asyncio.gather(*tasks)
            except KeyboardInterrupt:
                await finish_scan(scan_id, ScanStatus.INTERRUPTED)
                console.print("[yellow]Scan interrupted. Use --resume to continue.[/yellow]")
                return scan_id

            for results in results_list:
                for result in results:
                    await save_finding(
                        scan_id=scan_id,
                        endpoint_id=endpoint_id,
                        module=result.module,
                        severity=result.severity,
                        title=result.title,
                        description=result.description,
                        evidence=result.evidence,
                        request_data=result.request_data,
                        response_data=result.response_data,
                    )
                    total_findings += 1
                    finding_counts[result.severity] = finding_counts.get(result.severity, 0) + 1

            if endpoint_id:
                await mark_endpoint_scanned(endpoint_id)
            await update_scan_progress(scan_id, len(ep_dicts), i + 1)

        await finish_scan(scan_id, ScanStatus.COMPLETED)

        # print summary
        _print_summary(scan_id, total_findings, finding_counts)

    return scan_id


def _print_summary(scan_id: int, total: int, counts: dict[str, int]) -> None:
    """print a colored summary table of findings."""
    console.print()
    console.print(f"[bold]Scan #{scan_id} complete[/bold] — {total} finding(s)")

    if total == 0:
        console.print("[green]No vulnerabilities detected.[/green]")
        return

    table = Table(show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    severity_colors = {
        Severity.CRITICAL.value: "red bold",
        Severity.HIGH.value: "red",
        Severity.MEDIUM.value: "yellow",
        Severity.LOW.value: "blue",
        Severity.INFO.value: "dim",
    }

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = counts.get(sev.value, 0)
        if count > 0:
            style = severity_colors.get(sev.value, "")
            table.add_row(f"[{style}]{sev.value.upper()}[/{style}]", str(count))

    console.print(table)
    console.print(f"\n[dim]View details: parascan dashboard[/dim]")
