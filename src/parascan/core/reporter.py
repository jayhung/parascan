"""report generation — JSON and HTML reports from scan data."""

from __future__ import annotations

import json
import datetime
import pathlib
from typing import Any

from parascan.core.db import Severity
from parascan.core.state import get_all_scans, get_findings_for_scan


async def generate_json_report(scan_id: int) -> str:
    """generate a JSON report for a scan."""
    from parascan.core.state import get_session
    from parascan.core.db import Scan
    from sqlalchemy import select

    session = await get_session()
    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    await session.close()

    if not scan:
        return json.dumps({"error": "scan not found"})

    findings = await get_findings_for_scan(scan_id)

    report: dict[str, Any] = {
        "scan": {
            "id": scan.id,
            "target_url": scan.target_url,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "total_endpoints": scan.total_endpoints,
            "scanned_endpoints": scan.scanned_endpoints,
            "fingerprint": scan.fingerprint,
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": _count_by_severity(findings),
            "by_module": _count_by_module(findings),
        },
        "findings": [
            {
                "id": f.id,
                "module": f.module,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "request": f.request_data,
                "response": f.response_data,
                "found_at": f.found_at.isoformat() if f.found_at else None,
            }
            for f in findings
        ],
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
    }

    return json.dumps(report, indent=2)


async def generate_html_report(scan_id: int) -> str:
    """generate an HTML report for a scan."""
    from parascan.core.state import get_session
    from parascan.core.db import Scan
    from sqlalchemy import select

    session = await get_session()
    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    await session.close()

    if not scan:
        return "<h1>Scan not found</h1>"

    findings = await get_findings_for_scan(scan_id)
    severity_counts = _count_by_severity(findings)

    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "info": "#6b7280",
    }

    findings_html = ""
    for f in findings:
        color = severity_colors.get(f.severity, "#6b7280")
        evidence_html = f"<pre>{_escape(f.evidence or '')}</pre>" if f.evidence else ""
        request_html = f"<pre>{_escape(f.request_data or '')}</pre>" if f.request_data else ""
        response_html = f"<pre>{_escape(f.response_data or '')}</pre>" if f.response_data else ""

        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="severity" style="background:{color}">{f.severity.upper()}</span>
                <span class="module">{_escape(f.module)}</span>
                <strong>{_escape(f.title)}</strong>
            </div>
            <p>{_escape(f.description)}</p>
            {f'<h4>Evidence</h4>{evidence_html}' if evidence_html else ''}
            {f'<details><summary>Request</summary>{request_html}</details>' if request_html else ''}
            {f'<details><summary>Response</summary>{response_html}</details>' if response_html else ''}
        </div>
        """

    summary_items = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count:
            color = severity_colors[sev]
            summary_items += f'<span class="badge" style="background:{color}">{sev.upper()}: {count}</span> '

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>parascan Report — Scan #{scan.id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem; }}
        h1 {{ color: #f8fafc; margin-bottom: 0.5rem; }}
        h2 {{ color: #94a3b8; margin: 2rem 0 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
        h4 {{ margin: 0.5rem 0; color: #94a3b8; }}
        .meta {{ color: #64748b; margin-bottom: 2rem; }}
        .summary {{ display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 1rem 0; }}
        .badge {{ padding: 0.25rem 0.75rem; border-radius: 9999px; color: white;
                  font-size: 0.85rem; font-weight: 600; }}
        .finding {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
                    padding: 1rem; margin-bottom: 1rem; }}
        .finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }}
        .severity {{ padding: 0.15rem 0.5rem; border-radius: 4px; color: white;
                     font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
        .module {{ color: #64748b; font-size: 0.85rem; }}
        p {{ color: #cbd5e1; }}
        pre {{ background: #0f172a; border: 1px solid #334155; border-radius: 4px;
               padding: 0.75rem; overflow-x: auto; font-size: 0.8rem; color: #94a3b8;
               margin: 0.5rem 0; white-space: pre-wrap; word-break: break-all; }}
        details {{ margin: 0.5rem 0; }}
        summary {{ cursor: pointer; color: #60a5fa; font-size: 0.9rem; }}
        .fingerprint {{ background: #1e293b; border-radius: 4px; padding: 0.75rem;
                        font-family: monospace; font-size: 0.85rem; color: #94a3b8; }}
    </style>
</head>
<body>
    <h1>parascan Report</h1>
    <p class="meta">
        Scan #{scan.id} &mdash; {_escape(scan.target_url)}<br>
        Status: {scan.status} &mdash;
        {scan.total_endpoints} endpoints scanned &mdash;
        {len(findings)} finding(s)
    </p>

    <div class="summary">{summary_items}</div>

    {'<h2>Target Fingerprint</h2><div class="fingerprint">' + _escape(scan.fingerprint or '') + '</div>' if scan.fingerprint else ''}

    <h2>Findings ({len(findings)})</h2>
    {findings_html if findings_html else '<p>No vulnerabilities detected.</p>'}

    <p class="meta" style="margin-top:2rem">
        Generated by parascan v0.1.0 at {datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}
    </p>
</body>
</html>"""

    return html


def has_critical_or_high(findings: list) -> bool:
    """check if any findings are critical or high severity (for CI exit code)."""
    return any(f.severity in (Severity.CRITICAL.value, Severity.HIGH.value) for f in findings)


def _count_by_severity(findings: list) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _count_by_module(findings: list) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.module] = counts.get(f.module, 0) + 1
    return counts


def _escape(s: str) -> str:
    """escape HTML special characters."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
