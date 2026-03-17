"""core scan engine — orchestrates discovery, scanning, and reporting."""

from __future__ import annotations

import asyncio
import contextvars
import datetime
import logging
import time
from typing import TYPE_CHECKING, Any

import httpx
from rich.console import Console
from rich.table import Table

from parascan.core.auth import AuthManager
from parascan.core.config import TargetConfig
from parascan.core.db import ScanStatus, Severity
from parascan.core.fingerprint import fingerprint_target, format_fingerprint
from parascan.core.proxy import ProxyManager
from parascan.core.soft404 import Soft404Detector
from parascan.core.rate_limiter import RateLimiter
from parascan.core.scope import ScopeEnforcer
from parascan.core.db import get_session
from parascan.core.state import (
    create_scan,
    finish_scan,
    get_latest_scan,
    get_unscanned_endpoints,
    mark_endpoint_scanned,
    save_endpoints,
    save_finding,
    save_scan_event,
    save_scan_requests,
    update_scan_fingerprint,
    update_scan_progress,
)

if TYPE_CHECKING:
    from parascan.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger("parascan")
console = Console()

# context var to track which scanner module is currently active
_current_module: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_current_module", default="discovery"
)

# max response body size to store (100KB)
_MAX_BODY_SIZE = 100 * 1024


class RequestLogger:
    """captures all HTTP requests/responses via httpx event hooks."""

    def __init__(self, scan_id: int, enabled: bool = True) -> None:
        self.scan_id = scan_id
        self.enabled = enabled
        self._buffer: list[dict[str, Any]] = []
        self._pending_starts: dict[int, tuple[float, str, str, str | None, str | None]] = {}
        self._flush_size = 50

    def get_event_hooks(self) -> dict[str, list]:
        """return httpx event_hooks dict to attach to a client."""
        if not self.enabled:
            return {}
        return {
            "request": [self._on_request],
            "response": [self._on_response],
        }

    async def _on_request(self, request: httpx.Request) -> None:
        """capture request details before it is sent."""
        body = None
        try:
            raw = request.content
            if raw:
                body = raw.decode("utf-8", errors="replace")[:_MAX_BODY_SIZE]
        except Exception:
            body = None

        headers = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
        self._pending_starts[id(request)] = (
            time.monotonic(),
            str(request.method),
            str(request.url),
            headers,
            body,
        )

    async def _on_response(self, response: httpx.Response) -> None:
        """capture response and pair with the pending request."""
        request = response.request
        start_time, method, url, req_headers, req_body = self._pending_starts.pop(
            id(request), (time.monotonic(), str(request.method), str(request.url), None, None)
        )

        duration_ms = int((time.monotonic() - start_time) * 1000)

        # read body so it's available
        await response.aread()

        resp_headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        resp_body = None
        try:
            text = response.text
            resp_body = text[:_MAX_BODY_SIZE] if text else None
        except Exception:
            resp_body = "<binary>"

        module = _current_module.get()

        self._buffer.append({
            "scan_id": self.scan_id,
            "timestamp": datetime.datetime.now(datetime.UTC),
            "method": method,
            "url": url[:2048],
            "request_headers": req_headers,
            "request_body": req_body,
            "status_code": response.status_code,
            "response_headers": resp_headers,
            "response_body": resp_body,
            "duration_ms": duration_ms,
            "module": module,
            "finding_id": None,
        })

        if len(self._buffer) >= self._flush_size:
            await self.flush()

    async def flush(self) -> None:
        """flush buffered requests to the database."""
        if not self._buffer:
            return
        batch = self._buffer[:]
        self._buffer.clear()
        await save_scan_requests(batch)


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
    from parascan.scanners.info_disclosure import InfoDisclosureScanner
    from parascan.scanners.jwt import JWTScanner
    from parascan.scanners.open_redirect import OpenRedirectScanner
    from parascan.scanners.rate_limit import RateLimitScanner
    from parascan.scanners.sqli import SQLInjectionScanner
    from parascan.scanners.ssrf import SSRFScanner
    from parascan.scanners.tls import TLSScanner
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
        TLSScanner,
        InfoDisclosureScanner,
        RateLimitScanner,
    ]


def _select_scanners(
    config: TargetConfig,
) -> list[type[BaseScanner]]:
    """select scanner classes based on config filters.

    When --modules is explicitly set, include those modules regardless of
    default_enabled. When no --modules is set, exclude scanners where
    default_enabled is False.
    """
    all_scanners = _get_all_scanner_classes()

    if config.scan.modules:
        # explicit module list — include regardless of default_enabled
        all_scanners = [
            s for s in all_scanners if s.module_name in config.scan.modules
        ]
    else:
        # no explicit list — only include default-enabled scanners
        all_scanners = [
            s for s in all_scanners if s.default_enabled
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
    scan_id: int,
    soft404: Soft404Detector | None = None,
) -> list[dict[str, Any]]:
    """discover endpoints via crawling, openapi import, or fallback."""
    endpoints: list[dict[str, Any]] = []

    if config.openapi:
        from parascan.discovery.openapi import parse_openapi_spec

        spec_eps = parse_openapi_spec(config.openapi, config.url)
        endpoints.extend(spec_eps)
        console.print(f"[dim]  openapi: {len(spec_eps)} endpoint(s)[/dim]")
        await save_scan_event(
            scan_id, "info", "discovery.openapi",
            f"parsed {len(spec_eps)} endpoint(s) from OpenAPI spec",
        )

    # crawl the target for additional endpoints
    from parascan.discovery.crawler import crawl

    crawled = await crawl(client, config.url, scope, scan_id=scan_id, max_pages=50, max_depth=5)
    new_from_crawl = 0
    for ep in crawled:
        if not any(e["url"] == ep["url"] and e["method"] == ep["method"] for e in endpoints):
            endpoints.append(ep)
            new_from_crawl += 1
    console.print(f"[dim]  crawler: {new_from_crawl} endpoint(s)[/dim]")
    await save_scan_event(
        scan_id, "info", "discovery.crawl",
        f"crawler discovered {new_from_crawl} endpoint(s)",
    )

    # brute-force common directories/paths
    from parascan.discovery.directory_brute import brute_force_directories

    bruted = await brute_force_directories(client, config.url, scope, scan_id=scan_id, soft404=soft404)
    new_from_brute = 0
    for ep in bruted:
        if not any(e["url"] == ep["url"] and e["method"] == ep["method"] for e in endpoints):
            endpoints.append(ep)
            new_from_brute += 1
    console.print(f"[dim]  brute-force: {new_from_brute} endpoint(s)[/dim]")
    await save_scan_event(
        scan_id, "info", "discovery.brute",
        f"brute-force discovered {new_from_brute} endpoint(s)",
    )

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


async def run_scan(
    config: TargetConfig, resume: bool = False, findings_only: bool = False,
) -> int:
    """
    Execute a full scan against the target. Returns the scan id.

    If resume=True, picks up the most recent interrupted scan.
    If findings_only=True, skips request history logging.
    """
    auth = AuthManager(config.auth)
    proxy = ProxyManager(config.proxy)
    scope = ScopeEnforcer(config.scope)
    rate_limiter = RateLimiter(config.scan.rate_limit)
    semaphore = asyncio.Semaphore(config.scan.concurrency)

    # we need scan_id before creating the client for the logger,
    # but resume mode determines scan_id differently
    scan_id = 0
    if resume:
        latest = await get_latest_scan()
        if latest and latest.status == ScanStatus.INTERRUPTED.value:
            scan_id = latest.id
        else:
            console.print("[red]No interrupted scan found to resume.[/red]")
            return 0
    else:
        scan_id = await create_scan(config.url)

    req_logger = RequestLogger(scan_id, enabled=not findings_only)

    client_kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(30.0),
        "follow_redirects": True,
        "headers": auth.get_headers(),
        "event_hooks": req_logger.get_event_hooks(),
    }
    cookies = auth.get_cookies()
    if cookies:
        client_kwargs["cookies"] = cookies
    client_kwargs.update(proxy.get_transport_kwargs())

    async with httpx.AsyncClient(**client_kwargs) as client:
        # handle resume
        if resume:
            console.print(f"[yellow]Resuming scan #{scan_id}[/yellow]")
            unscanned = await get_unscanned_endpoints(scan_id)
            ep_dicts = [
                {"url": ep.url, "method": ep.method, "params": ep.params, "_id": ep.id}
                for ep in unscanned
            ]
        else:
            console.print(f"[bold green]Starting scan #{scan_id}[/bold green] → {config.url}")

            # fingerprint
            _current_module.set("fingerprint")
            console.print("[dim]Fingerprinting target...[/dim]")
            fp_data = await fingerprint_target(client, config.url, scan_id=scan_id)
            fp_str = format_fingerprint(fp_data)
            await update_scan_fingerprint(scan_id, fp_str)
            if fp_str != "No fingerprint data detected":
                console.print(f"[cyan]{fp_str}[/cyan]")

            # calibrate soft-404 detector
            _current_module.set("discovery")
            soft404 = Soft404Detector()
            await soft404.calibrate(client, config.url)
            if soft404._calibrated:
                console.print("[dim]Soft-404 baseline captured[/dim]")
                await save_scan_event(
                    scan_id, "info", "soft404",
                    soft404.summary,
                    detail=soft404.baselines_json,
                )

            # discover endpoints
            console.print("[dim]Discovering endpoints...[/dim]")
            endpoints = await _discover_endpoints(client, config, scope, scan_id, soft404=soft404)
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

        # inject soft-404 detector into scanners that support it
        if not resume:
            from parascan.scanners.info_disclosure import InfoDisclosureScanner
            for s in scanners:
                if isinstance(s, InfoDisclosureScanner):
                    s.soft404 = soft404

        console.print(
            f"[dim]Running {len(scanners)} scanner(s) against {len(ep_dicts)} endpoint(s)[/dim]"
        )

        # scan each endpoint
        total_findings = 0
        finding_counts: dict[str, int] = {}

        for i, ep in enumerate(ep_dicts):
            endpoint_id = ep.pop("_id", None)

            async def scan_endpoint(scanner: BaseScanner) -> list[ScanResult]:
                _current_module.set(scanner.module_name)
                async with semaphore:
                    return await _run_scanner_on_endpoint(
                        scanner, client, ep, rate_limiter
                    )

            tasks = [scan_endpoint(s) for s in scanners]

            try:
                results_list = await asyncio.gather(*tasks)
            except KeyboardInterrupt:
                await req_logger.flush()
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
                        remediation=result.remediation,
                        soc2_criteria=result.soc2_criteria,
                    )
                    total_findings += 1
                    finding_counts[result.severity] = finding_counts.get(result.severity, 0) + 1

            if endpoint_id:
                await mark_endpoint_scanned(endpoint_id)
            await update_scan_progress(scan_id, len(ep_dicts), i + 1)

        # log soft-404 filtering stats
        if not resume and soft404._calibrated and soft404.filtered_count > 0:
            await save_scan_event(
                scan_id, "info", "soft404",
                f"{soft404.filtered_count} response(s) filtered as soft-404 false positives",
            )

        # flush any remaining logged requests
        await req_logger.flush()
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


async def run_retest(
    config: TargetConfig, retest_scan_id: int, findings_only: bool = False,
) -> int:
    """re-run scanners from a previous scan to verify fixes.

    Only runs modules that produced findings in the reference scan, against the
    same endpoints. Marks each finding as 'fixed', 'still_present', or 'new'.
    """
    from parascan.core.state import get_findings_for_scan as get_findings
    from parascan.core.db import Scan
    from sqlalchemy import select

    # load the reference scan
    session = await get_session()
    result = await session.execute(select(Scan).where(Scan.id == retest_scan_id))
    ref_scan = result.scalar_one_or_none()
    await session.close()

    if not ref_scan:
        console.print(f"[red]Scan #{retest_scan_id} not found.[/red]")
        return 0

    ref_findings = await get_findings(retest_scan_id)
    if not ref_findings:
        console.print(f"[yellow]Scan #{retest_scan_id} had no findings. Nothing to retest.[/yellow]")
        return 0

    # determine which modules and endpoints to retest
    ref_modules = set(f.module for f in ref_findings)
    ref_titles = set(f.title for f in ref_findings)

    console.print(f"[bold cyan]Retesting scan #{retest_scan_id}[/bold cyan] — {len(ref_findings)} finding(s) across {len(ref_modules)} module(s)")

    # create new scan record
    scan_id = await create_scan(config.url or ref_scan.target_url)
    # update scan to mark as retest
    session = await get_session()
    from sqlalchemy import update as sql_update
    async with session.begin():
        await session.execute(
            sql_update(Scan).where(Scan.id == scan_id).values(retest_of=retest_scan_id)
        )
    await session.close()

    req_logger = RequestLogger(scan_id, enabled=not findings_only)

    # set up HTTP client
    auth = AuthManager(config.auth)
    proxy = ProxyManager(config.proxy)
    rate_limiter = RateLimiter(config.scan.rate_limit)
    semaphore = asyncio.Semaphore(config.scan.concurrency)

    client_kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(30.0),
        "follow_redirects": True,
        "headers": auth.get_headers(),
        "event_hooks": req_logger.get_event_hooks(),
    }
    cookies = auth.get_cookies()
    if cookies:
        client_kwargs["cookies"] = cookies
    client_kwargs.update(proxy.get_transport_kwargs())

    async with httpx.AsyncClient(**client_kwargs) as client:
        # use same target URL
        target_url = config.url or ref_scan.target_url
        endpoints = [{"url": target_url, "method": "GET", "params": {}}]
        saved_ids = await save_endpoints(scan_id, endpoints)
        await update_scan_progress(scan_id, len(endpoints), 0)

        # only run modules that had findings
        all_scanners = _get_all_scanner_classes()
        scanners = [cls() for cls in all_scanners if cls.module_name in ref_modules]

        console.print(f"[dim]Running {len(scanners)} module(s) against {len(endpoints)} endpoint(s)[/dim]")

        total_findings = 0
        finding_counts: dict[str, int] = {}
        new_titles: set[str] = set()

        for i, ep in enumerate(endpoints):
            endpoint_id = saved_ids[i] if i < len(saved_ids) else None

            async def scan_ep(scanner: BaseScanner) -> list[ScanResult]:
                _current_module.set(scanner.module_name)
                async with semaphore:
                    return await _run_scanner_on_endpoint(scanner, client, ep, rate_limiter)

            tasks = [scan_ep(s) for s in scanners]
            results_list = await asyncio.gather(*tasks)

            for scan_results in results_list:
                for r in scan_results:
                    # determine retest status
                    if r.title in ref_titles:
                        retest_status = "still_present"
                    else:
                        retest_status = "new"
                    new_titles.add(r.title)

                    await save_finding(
                        scan_id=scan_id,
                        endpoint_id=endpoint_id,
                        module=r.module,
                        severity=r.severity,
                        title=r.title,
                        description=r.description,
                        evidence=r.evidence,
                        request_data=r.request_data,
                        response_data=r.response_data,
                        remediation=r.remediation,
                        soc2_criteria=r.soc2_criteria,
                        retest_status=retest_status,
                    )
                    total_findings += 1
                    finding_counts[r.severity] = finding_counts.get(r.severity, 0) + 1

            if endpoint_id:
                await mark_endpoint_scanned(endpoint_id)
            await update_scan_progress(scan_id, len(endpoints), i + 1)

        await req_logger.flush()

        # mark previously-found issues that are now absent as "fixed"
        fixed_titles = ref_titles - new_titles
        for ref_f in ref_findings:
            if ref_f.title in fixed_titles:
                await save_finding(
                    scan_id=scan_id,
                    endpoint_id=None,
                    module=ref_f.module,
                    severity=ref_f.severity,
                    title=ref_f.title,
                    description=ref_f.description,
                    remediation=ref_f.remediation,
                    soc2_criteria=ref_f.soc2_criteria,
                    retest_status="fixed",
                )

        await finish_scan(scan_id, ScanStatus.COMPLETED)

        # print retest summary
        still_present = sum(1 for t in new_titles if t in ref_titles)
        new_count = sum(1 for t in new_titles if t not in ref_titles)
        fixed_count = len(fixed_titles)

        console.print()
        console.print(f"[bold]Retest #{scan_id} complete[/bold] (reference: #{retest_scan_id})")
        retest_table = Table(show_header=True)
        retest_table.add_column("Status", style="bold")
        retest_table.add_column("Count", justify="right")
        if fixed_count:
            retest_table.add_row("[green]Fixed[/green]", str(fixed_count))
        if still_present:
            retest_table.add_row("[red]Still Present[/red]", str(still_present))
        if new_count:
            retest_table.add_row("[yellow]New[/yellow]", str(new_count))
        console.print(retest_table)
        console.print(f"\n[dim]View details: parascan dashboard[/dim]")

    return scan_id


async def run_auth_comparison(
    config: TargetConfig, findings_only: bool = False,
) -> int:
    """test endpoints with and without authentication to detect broken access control.

    Makes an unauthenticated request to each discovered endpoint and compares
    the response to the authenticated version.
    """
    auth = AuthManager(config.auth)
    proxy = ProxyManager(config.proxy)
    scope = ScopeEnforcer(config.scope)
    rate_limiter = RateLimiter(config.scan.rate_limit)

    scan_id = await create_scan(config.url)
    req_logger = RequestLogger(scan_id, enabled=not findings_only)
    _current_module.set("auth-check")

    authed_kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(30.0),
        "follow_redirects": True,
        "headers": auth.get_headers(),
        "event_hooks": req_logger.get_event_hooks(),
    }
    cookies = auth.get_cookies()
    if cookies:
        authed_kwargs["cookies"] = cookies
    authed_kwargs.update(proxy.get_transport_kwargs())

    unauthed_kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(30.0),
        "follow_redirects": True,
        "event_hooks": req_logger.get_event_hooks(),
    }
    unauthed_kwargs.update(proxy.get_transport_kwargs())

    console.print(f"[bold cyan]Auth comparison scan #{scan_id}[/bold cyan] → {config.url}")

    async with httpx.AsyncClient(**authed_kwargs) as authed_client:
        async with httpx.AsyncClient(**unauthed_kwargs) as unauthed_client:
            # discover endpoints
            console.print("[dim]Discovering endpoints...[/dim]")
            endpoints = await _discover_endpoints(authed_client, config, scope, scan_id)
            saved_ids = await save_endpoints(scan_id, endpoints)
            await update_scan_progress(scan_id, len(endpoints), 0)
            console.print(f"[green]Found {len(endpoints)} endpoint(s)[/green]")

            total_findings = 0
            finding_counts: dict[str, int] = {}

            for i, ep in enumerate(endpoints):
                endpoint_id = saved_ids[i] if i < len(saved_ids) else None
                url = ep["url"]
                method = ep.get("method", "GET")

                await rate_limiter.acquire()

                # authenticated request
                try:
                    authed_resp = await authed_client.request(method, url)
                except Exception:
                    continue

                # unauthenticated request
                try:
                    unauthed_resp = await unauthed_client.request(method, url)
                except Exception:
                    continue

                # compare: if unauthed gets same status and similar content, flag it
                if (
                    unauthed_resp.status_code == authed_resp.status_code
                    and unauthed_resp.status_code in (200, 201)
                    and len(unauthed_resp.text) > 50
                ):
                    # check content similarity
                    authed_len = len(authed_resp.text)
                    unauthed_len = len(unauthed_resp.text)
                    size_ratio = min(authed_len, unauthed_len) / max(authed_len, 1)

                    if size_ratio > 0.5:
                        await save_finding(
                            scan_id=scan_id,
                            endpoint_id=endpoint_id,
                            module="auth-check",
                            severity="high",
                            title=f"Endpoint accessible without authentication: {method} {url}",
                            description=(
                                f"The endpoint {method} {url} returns similar content "
                                f"({unauthed_len}B) without authentication as with authentication "
                                f"({authed_len}B). This may indicate missing access controls."
                            ),
                            evidence=(
                                f"Authed: HTTP {authed_resp.status_code} ({authed_len}B), "
                                f"Unauthed: HTTP {unauthed_resp.status_code} ({unauthed_len}B)"
                            ),
                            remediation=(
                                "Add authentication middleware to protect this endpoint. "
                                "Verify that all API endpoints require valid credentials "
                                "before returning data. Use role-based access control (RBAC) "
                                "to enforce authorization."
                            ),
                            soc2_criteria="CC6.1",
                        )
                        total_findings += 1
                        finding_counts["high"] = finding_counts.get("high", 0) + 1

                if endpoint_id:
                    await mark_endpoint_scanned(endpoint_id)
                await update_scan_progress(scan_id, len(endpoints), i + 1)

            await req_logger.flush()
            await finish_scan(scan_id, ScanStatus.COMPLETED)
            _print_summary(scan_id, total_findings, finding_counts)

    return scan_id
