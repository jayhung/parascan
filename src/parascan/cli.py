"""parascan CLI — zero-config penetration testing from the command line."""

from __future__ import annotations

import asyncio
import pathlib
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from parascan import __version__

app = typer.Typer(
    name="parascan",
    help="A modular web application penetration testing tool.",
    no_args_is_help=True,
)
console = Console()

DISCLAIMER = """
[bold red]LEGAL DISCLAIMER[/bold red]

parascan is a penetration testing tool intended for [bold]authorized security testing only[/bold].

By proceeding, you confirm that:
  1. You have [bold]written authorization[/bold] to test the target system.
  2. You understand that unauthorized testing is [bold]illegal[/bold].
  3. You accept full responsibility for your actions.

[dim]Unauthorized access to computer systems is a criminal offense in most jurisdictions.
parascan contributors accept no liability for misuse of this tool.[/dim]
"""

# path to store disclaimer acceptance per target
_DISCLAIMER_CACHE = pathlib.Path.home() / ".parascan" / ".accepted_targets"


def _check_disclaimer(target: str) -> bool:
    """check if the user has already accepted the disclaimer for this target."""
    if _DISCLAIMER_CACHE.exists():
        accepted = _DISCLAIMER_CACHE.read_text().splitlines()
        if target in accepted:
            return True
    return False


def _save_disclaimer(target: str) -> None:
    """save that the user accepted the disclaimer for a target."""
    _DISCLAIMER_CACHE.parent.mkdir(parents=True, exist_ok=True)
    existing = ""
    if _DISCLAIMER_CACHE.exists():
        existing = _DISCLAIMER_CACHE.read_text()
    if target not in existing.splitlines():
        with open(_DISCLAIMER_CACHE, "a") as f:
            f.write(target + "\n")


def _show_disclaimer(target: str) -> None:
    """display legal disclaimer and require confirmation."""
    if _check_disclaimer(target):
        return

    console.print(Panel(DISCLAIMER, title="parascan", border_style="red"))
    confirmed = typer.confirm(
        f"Do you have authorization to test {target}?", default=False
    )
    if not confirmed:
        console.print("[red]Scan aborted.[/red]")
        raise typer.Exit(1)

    _save_disclaimer(target)


@app.command()
def scan(
    url: Optional[str] = typer.Argument(None, help="Target URL to scan"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="YAML config file path"),
    bearer: Optional[str] = typer.Option(None, "--bearer", help="Bearer token for authentication"),
    cookie: Optional[str] = typer.Option(None, "--cookie", help="Cookie string (e.g. 'session=abc')"),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", help="API key as 'Header-Name: value'"
    ),
    basic_auth: Optional[str] = typer.Option(
        None, "--basic-auth", help="Basic auth as 'username:password'"
    ),
    modules: Optional[str] = typer.Option(
        None, "--modules", "-m", help="Comma-separated scanner modules to run"
    ),
    exclude_modules: Optional[str] = typer.Option(
        None, "--exclude-modules", help="Comma-separated modules to skip"
    ),
    concurrency: int = typer.Option(10, "--concurrency", help="Max concurrent requests"),
    rate_limit: int = typer.Option(10, "--rate-limit", help="Max requests per second"),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)"
    ),
    openapi: Optional[str] = typer.Option(
        None, "--openapi", help="OpenAPI/Swagger spec file for endpoint discovery"
    ),
    ci: bool = typer.Option(False, "--ci", help="CI/CD mode: JSON output, exit 1 on critical/high"),
    resume: bool = typer.Option(False, "--resume", help="Resume the most recent interrupted scan"),
    retest: Optional[int] = typer.Option(None, "--retest", help="Re-run scan against a previous scan ID to verify fixes"),
    test_unauth: bool = typer.Option(False, "--test-unauth", help="Test endpoints without auth to detect broken access control"),
    findings_only: bool = typer.Option(False, "--findings-only", help="Skip request history logging for a lighter scan"),
) -> None:
    """Run a penetration test against a web application."""
    if resume:
        # resume mode doesn't need a URL
        asyncio.run(_run_scan_async(
            url="",
            config_path=config,
            bearer=bearer,
            cookie=cookie,
            api_key=api_key,
            basic_auth=basic_auth,
            modules=modules,
            exclude_modules=exclude_modules,
            concurrency=concurrency,
            rate_limit=rate_limit,
            proxy=proxy,
            openapi=openapi,
            ci=ci,
            resume=True,
            retest=None,
            test_unauth=False,
            findings_only=findings_only,
        ))
        return

    if not url and not config:
        console.print("[red]Error: provide a target URL or --config file.[/red]")
        raise typer.Exit(1)

    # if config provided but no url, load url from config
    if config and not url:
        from parascan.core.config import load_config

        target_config = load_config(config)
        url = target_config.url

    if not url:
        console.print("[red]Error: no target URL found.[/red]")
        raise typer.Exit(1)

    _show_disclaimer(url)

    asyncio.run(_run_scan_async(
        url=url,
        config_path=config,
        bearer=bearer,
        cookie=cookie,
        api_key=api_key,
        basic_auth=basic_auth,
        modules=modules,
        exclude_modules=exclude_modules,
        concurrency=concurrency,
        rate_limit=rate_limit,
        proxy=proxy,
        openapi=openapi,
        ci=ci,
        resume=False,
        retest=retest,
        test_unauth=test_unauth,
        findings_only=findings_only,
    ))


async def _run_scan_async(
    url: str,
    config_path: str | None,
    bearer: str | None,
    cookie: str | None,
    api_key: str | None,
    basic_auth: str | None,
    modules: str | None,
    exclude_modules: str | None,
    concurrency: int,
    rate_limit: int,
    proxy: str | None,
    openapi: str | None,
    ci: bool,
    resume: bool,
    retest: int | None = None,
    test_unauth: bool = False,
    findings_only: bool = False,
) -> None:
    """async scan runner."""
    from parascan.core.config import build_config_from_cli, load_config
    from parascan.core.engine import run_scan, run_retest
    from parascan.core.reporter import generate_json_report, has_critical_or_high
    from parascan.core.state import get_findings_for_scan

    if config_path:
        target_config = load_config(config_path)
        # CLI flags override config values
        if bearer:
            target_config.auth.bearer = bearer
        if cookie:
            target_config.auth.cookie = cookie
        if proxy:
            target_config.proxy.url = proxy
        if modules:
            target_config.scan.modules = [m.strip() for m in modules.split(",")]
        if exclude_modules:
            target_config.scan.exclude_modules = [m.strip() for m in exclude_modules.split(",")]
        target_config.scan.concurrency = concurrency
        target_config.scan.rate_limit = rate_limit
    else:
        target_config = build_config_from_cli(
            url=url,
            bearer=bearer,
            cookie=cookie,
            api_key=api_key,
            basic_auth=basic_auth,
            modules=modules,
            exclude_modules=exclude_modules,
            concurrency=concurrency,
            rate_limit=rate_limit,
            proxy=proxy,
            openapi=openapi,
        )

    if retest:
        scan_id = await run_retest(target_config, retest_scan_id=retest, findings_only=findings_only)
    elif test_unauth:
        from parascan.core.engine import run_auth_comparison
        scan_id = await run_auth_comparison(target_config, findings_only=findings_only)
    else:
        scan_id = await run_scan(target_config, resume=resume, findings_only=findings_only)

    if ci and scan_id:
        report = await generate_json_report(scan_id)
        print(report)
        findings = await get_findings_for_scan(scan_id)
        if has_critical_or_high(findings):
            raise SystemExit(1)


@app.command()
def dashboard(
    port: int = typer.Option(8000, "--port", "-p", help="Port to serve the dashboard on"),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to"),
) -> None:
    """Launch the web dashboard to browse scan results."""
    import uvicorn

    console.print(f"[bold green]parascan dashboard[/bold green] → http://{host}:{port}")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    uvicorn.run("parascan.web.app:app", host=host, port=port, log_level="warning")


@app.command()
def version() -> None:
    """Show the parascan version."""
    console.print(f"parascan v{__version__}")


@app.command()
def modules() -> None:
    """List all available scanner modules."""
    from parascan.core.engine import _get_all_scanner_classes

    from rich.table import Table

    table = Table(title="Available Scanner Modules")
    table.add_column("Module", style="cyan")
    table.add_column("Description")

    for cls in _get_all_scanner_classes():
        table.add_row(cls.module_name, cls.description)

    console.print(table)


if __name__ == "__main__":
    app()
