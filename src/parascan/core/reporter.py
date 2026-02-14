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
                "remediation": f.remediation,
                "soc2_criteria": f.soc2_criteria,
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


SOC2_CRITERIA_DESCRIPTIONS = {
    "CC6.1": "Logical and Physical Access Controls",
    "CC6.6": "System Boundary Protection",
    "CC6.7": "Data Transmission and Encryption",
    "CC6.8": "Software and Data Integrity",
    "CC7.1": "System Monitoring",
    "CC7.2": "Anomaly and Incident Detection",
}

SOC2_REMEDIATION_TIMELINES = {
    "critical": "Immediate — remediate within 24-48 hours",
    "high": "Urgent — remediate within 7 days",
    "medium": "Standard — remediate within 30 days",
    "low": "Planned — remediate within 90 days",
    "info": "Advisory — address during next development cycle",
}


async def generate_html_report(scan_id: int) -> str:
    """generate a unified standalone HTML report with executive summary,
    methodology, findings by severity, and SOC 2 criteria summary."""
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
    by_module = _count_by_module(findings)

    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "info": "#6b7280",
    }

    # executive summary stats
    total = len(findings)
    crit_count = severity_counts.get("critical", 0)
    high_count = severity_counts.get("high", 0)
    med_count = severity_counts.get("medium", 0)
    low_info_count = severity_counts.get("low", 0) + severity_counts.get("info", 0)

    # group findings by severity
    severity_order = ["critical", "high", "medium", "low", "info"]
    grouped: dict[str, list] = {s: [] for s in severity_order}
    for f in findings:
        if f.severity in grouped:
            grouped[f.severity].append(f)

    # group by SOC 2 criteria
    by_criteria: dict[str, list] = {}
    for f in findings:
        criteria = getattr(f, "soc2_criteria", None)
        if criteria:
            by_criteria.setdefault(criteria, []).append(f)

    # determine pass/fail per criteria
    criteria_status: dict[str, str] = {}
    for criteria_id in SOC2_CRITERIA_DESCRIPTIONS:
        criteria_findings = by_criteria.get(criteria_id, [])
        if not criteria_findings:
            criteria_status[criteria_id] = "pass"
        elif any(f.severity in ("critical", "high") for f in criteria_findings):
            criteria_status[criteria_id] = "fail"
        else:
            criteria_status[criteria_id] = "warn"

    status_colors = {"pass": "#166534", "fail": "#dc2626", "warn": "#ca8a04"}
    status_text_colors = {"pass": "#4ade80", "fail": "#fca5a5", "warn": "#fde68a"}
    criteria_failing = sum(1 for s in criteria_status.values() if s == "fail")

    # build severity badge row
    summary_items = ""
    for sev in severity_order:
        count = severity_counts.get(sev, 0)
        if count:
            color = severity_colors[sev]
            summary_items += f'<span class="badge" style="background:{color}">{sev.upper()}: {count}</span> '

    module_chips = ""
    for mod, count in by_module.items():
        module_chips += f'<span class="chip">{_escape(mod)}: {count}</span> '

    # build SOC 2 criteria summary table
    criteria_table_html = ""
    for criteria_id, desc in SOC2_CRITERIA_DESCRIPTIONS.items():
        status = criteria_status[criteria_id]
        sbg = status_colors[status]
        sfg = status_text_colors[status]
        count = len(by_criteria.get(criteria_id, []))
        criteria_table_html += (
            f'<tr><td><span class="criteria-status" style="background:{sbg};color:{sfg}">'
            f'{status.upper()}</span></td>'
            f'<td>{criteria_id}</td><td>{desc}</td>'
            f'<td style="text-align:right">{count}</td></tr>'
        )

    # build finding HTML grouped by severity
    findings_html = ""
    for sev in severity_order:
        sev_findings = grouped[sev]
        if not sev_findings:
            continue
        sev_color = severity_colors.get(sev, "#6b7280")
        findings_html += f'<h2 style="color:{sev_color}">{sev.upper()} ({len(sev_findings)})</h2>'

        for f in sev_findings:
            color = severity_colors.get(f.severity, "#6b7280")
            evidence_html = f"<pre>{_escape(f.evidence or '')}</pre>" if f.evidence else ""
            request_html = f"<pre>{_escape(f.request_data or '')}</pre>" if f.request_data else ""
            response_html = f"<pre>{_escape(f.response_data or '')}</pre>" if f.response_data else ""
            remediation_html = ""
            if f.remediation:
                timeline = SOC2_REMEDIATION_TIMELINES.get(f.severity, "")
                remediation_html = (
                    f'<div class="remediation"><h4>How to fix</h4>'
                    f'<p>{_escape(f.remediation)}</p>'
                    f'<p class="timeline"><strong>Remediation timeline:</strong> {timeline}</p>'
                    f'</div>'
                )
            soc2_html = ""
            if f.soc2_criteria:
                soc2_html = f' <span class="soc2-tag">SOC 2 {_escape(f.soc2_criteria)}</span>'

            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="severity" style="background:{color}">{f.severity.upper()}</span>
                    <span class="module">{_escape(f.module)}</span>
                    <strong>{_escape(f.title)}</strong>{soc2_html}
                </div>
                <p>{_escape(f.description)}</p>
                {f'<h4>Evidence</h4>{evidence_html}' if evidence_html else ''}
                {f'<details><summary>Request</summary>{request_html}</details>' if request_html else ''}
                {f'<details><summary>Response</summary>{response_html}</details>' if response_html else ''}
                {remediation_html}
            </div>
            """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>parascan Report — Scan #{scan.id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem;
               max-width: 1000px; margin: 0 auto; }}
        h1 {{ color: #f8fafc; margin-bottom: 0.5rem; }}
        h2 {{ color: #94a3b8; margin: 2rem 0 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
        h3 {{ color: #f8fafc; font-size: 1.1rem; }}
        h4 {{ margin: 0.5rem 0; color: #94a3b8; }}
        .meta {{ color: #64748b; }}
        .summary {{ display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 1rem 0; }}
        .badge {{ padding: 0.25rem 0.75rem; border-radius: 9999px; color: white;
                  font-size: 0.85rem; font-weight: 600; }}
        .chip {{ display: inline-block; background: #1e293b; padding: 0.2rem 0.5rem;
                 border-radius: 9999px; font-size: 0.75rem; color: #94a3b8; margin: 0.15rem; }}
        .finding {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
                    padding: 1rem; margin-bottom: 1rem; }}
        .finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem;
                           flex-wrap: wrap; }}
        .severity {{ padding: 0.15rem 0.5rem; border-radius: 4px; color: white;
                     font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
        .module {{ color: #64748b; font-size: 0.85rem; }}
        p {{ color: #cbd5e1; font-size: 0.9rem; }}
        pre {{ background: #0f172a; border: 1px solid #334155; border-radius: 4px;
               padding: 0.75rem; overflow-x: auto; font-size: 0.8rem; color: #94a3b8;
               margin: 0.5rem 0; white-space: pre-wrap; word-break: break-all; }}
        details {{ margin: 0.5rem 0; }}
        summary {{ cursor: pointer; color: #60a5fa; font-size: 0.9rem; }}
        .remediation {{ background: #0f2318; border: 1px solid #166534; border-radius: 6px;
                        padding: 0.75rem; margin: 0.5rem 0; }}
        .remediation h4 {{ color: #4ade80; margin-bottom: 0.25rem; }}
        .remediation p {{ color: #86efac; font-size: 0.85rem; }}
        .timeline {{ color: #64748b; font-size: 0.8rem; margin-top: 0.25rem; }}
        .soc2-tag {{ display: inline-block; background: #1e293b; border: 1px solid #334155;
                     padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.7rem;
                     color: #94a3b8; margin-left: 0.5rem; font-family: monospace; }}
        .fingerprint {{ background: #1e293b; border-radius: 4px; padding: 0.75rem;
                        font-family: monospace; font-size: 0.85rem; color: #94a3b8; }}
        .exec-summary {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
                         padding: 1.5rem; margin: 1.5rem 0; }}
        .exec-summary h2 {{ margin-top: 0; border: none; padding: 0; }}
        .exec-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem;
                      margin-top: 1rem; }}
        .exec-stat {{ background: #0f172a; border-radius: 8px; padding: 1rem; text-align: center; }}
        .exec-stat .number {{ font-size: 1.75rem; font-weight: 700; }}
        .exec-stat .label {{ color: #64748b; font-size: 0.8rem; }}
        .methodology {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
                        padding: 1rem; margin: 1rem 0; }}
        .methodology h2 {{ margin-top: 0; border: none; padding: 0; }}
        .methodology ul {{ margin: 0.5rem 0 0 1.5rem; color: #94a3b8; font-size: 0.9rem; }}
        .criteria-table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0; }}
        .criteria-table th {{ text-align: left; color: #94a3b8; font-weight: 500; font-size: 0.85rem;
                              padding: 0.5rem; border-bottom: 1px solid #334155; }}
        .criteria-table td {{ padding: 0.5rem; border-bottom: 1px solid #1e293b; font-size: 0.9rem; }}
        .criteria-status {{ padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem;
                            font-weight: 700; }}
        .no-findings {{ color: #4ade80; font-style: italic; }}
    </style>
</head>
<body>
    <h1>parascan Report</h1>
    <p class="meta">
        Scan #{scan.id} &mdash; {_escape(scan.target_url)}<br>
        {scan.started_at.strftime('%Y-%m-%d %H:%M UTC') if scan.started_at else ''} &mdash;
        {scan.total_endpoints} endpoints scanned
    </p>

    <div class="exec-summary">
        <h2>Executive Summary</h2>
        <p>Automated penetration testing identified <strong>{total} finding(s)</strong>
        across {scan.total_endpoints} endpoint(s).</p>
        <div class="exec-grid">
            <div class="exec-stat">
                <div class="number" style="color:#dc2626">{crit_count}</div>
                <div class="label">Critical</div>
            </div>
            <div class="exec-stat">
                <div class="number" style="color:#ea580c">{high_count}</div>
                <div class="label">High</div>
            </div>
            <div class="exec-stat">
                <div class="number" style="color:#ca8a04">{med_count}</div>
                <div class="label">Medium</div>
            </div>
            <div class="exec-stat">
                <div class="number" style="color:#60a5fa">{low_info_count}</div>
                <div class="label">Low / Info</div>
            </div>
        </div>
    </div>

    <div class="methodology">
        <h2>Methodology</h2>
        <p>Automated penetration testing was performed using parascan against the target
        application. The following test categories were executed:</p>
        <ul>
            <li>Injection testing (SQL, XSS, command injection, XXE)</li>
            <li>Authentication and session management (JWT, CSRF, IDOR)</li>
            <li>Transport security (TLS configuration, HSTS)</li>
            <li>Security header analysis</li>
            <li>Information disclosure (debug endpoints, version headers)</li>
            <li>API-specific testing (GraphQL introspection, batch attacks)</li>
            <li>Server-side request forgery (SSRF)</li>
            <li>Open redirect detection</li>
        </ul>
    </div>

    <div class="summary">{summary_items}</div>
    <div>{module_chips}</div>

    {'<h2>Target Fingerprint</h2><div class="fingerprint">' + _escape(scan.fingerprint or '') + '</div>' if scan.fingerprint else ''}

    <h2>SOC 2 Compliance Summary</h2>
    <table class="criteria-table">
        <thead><tr><th>Status</th><th>Criteria</th><th>Description</th><th style="text-align:right">Findings</th></tr></thead>
        <tbody>{criteria_table_html}</tbody>
    </table>

    {findings_html if findings_html else '<p class="no-findings">No vulnerabilities detected.</p>'}

    <p class="meta" style="margin-top:2rem">
        Generated by parascan v0.1.0 at {datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}
    </p>
</body>
</html>"""

    return html


# keep as alias for backward compatibility
generate_compliance_report = generate_html_report


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
