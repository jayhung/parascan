"""FastAPI web dashboard for browsing scan results."""

from __future__ import annotations

import pathlib

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="parascan dashboard")

TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
STATIC_DIR = pathlib.Path(__file__).parent / "static"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """scan history page."""
    from parascan.core.state import get_all_scans

    scans = await get_all_scans()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "scans": scans,
    })


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int):
    """scan detail page with findings."""
    from parascan.core.db import Scan
    from parascan.core.state import get_findings_for_scan, get_session
    from sqlalchemy import select

    session = await get_session()
    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    await session.close()

    if not scan:
        return HTMLResponse("<h1>Scan not found</h1>", status_code=404)

    findings = await get_findings_for_scan(scan_id)

    # group findings by severity
    severity_order = ["critical", "high", "medium", "low", "info"]
    grouped: dict[str, list] = {s: [] for s in severity_order}
    for f in findings:
        if f.severity in grouped:
            grouped[f.severity].append(f)

    # count by module
    by_module: dict[str, int] = {}
    for f in findings:
        by_module[f.module] = by_module.get(f.module, 0) + 1

    # group by SOC 2 criteria
    from parascan.core.reporter import SOC2_CRITERIA_DESCRIPTIONS, SOC2_REMEDIATION_TIMELINES
    from parascan.core.state import (
        get_scan_request_count,
        get_scan_event_count,
        get_scan_request_stats,
        get_scan_requests,
    )

    criteria_grouped: dict[str, list] = {}
    for f in findings:
        if f.soc2_criteria:
            criteria_grouped.setdefault(f.soc2_criteria, []).append(f)

    request_count = await get_scan_request_count(scan_id)
    event_count = await get_scan_event_count(scan_id)
    request_stats = await get_scan_request_stats(scan_id)
    scan_requests = await get_scan_requests(scan_id, limit=500)

    # compute scan duration
    duration_str = ""
    if scan.started_at and scan.finished_at:
        delta = scan.finished_at - scan.started_at
        mins = int(delta.total_seconds() // 60)
        secs = int(delta.total_seconds() % 60)
        duration_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    return templates.TemplateResponse("scan.html", {
        "request": request,
        "scan": scan,
        "findings": findings,
        "grouped": grouped,
        "by_module": by_module,
        "total": len(findings),
        "soc2_criteria": SOC2_CRITERIA_DESCRIPTIONS,
        "criteria_grouped": criteria_grouped,
        "request_count": request_count,
        "event_count": event_count,
        "request_stats": request_stats,
        "duration_str": duration_str,
        "remediation_timelines": SOC2_REMEDIATION_TIMELINES,
        "scan_requests": scan_requests,
    })


@app.get("/scan/{scan_id}/json")
async def scan_json(scan_id: int):
    """JSON export endpoint."""
    from parascan.core.reporter import generate_json_report
    import json

    report = await generate_json_report(scan_id)
    return JSONResponse(content=json.loads(report))


@app.get("/scan/{scan_id}/report")
async def scan_report(scan_id: int):
    """redirect to scan detail view (report merged into scan view)."""
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url=f"/scan/{scan_id}")


@app.get("/scan/{scan_id}/history/json")
async def scan_history_json(
    scan_id: int,
    module: str | None = None,
    status_code: int | None = None,
    limit: int = 200,
    offset: int = 0,
):
    """paginated request history for the History tab."""
    from parascan.core.state import get_scan_requests, get_scan_request_count

    requests = await get_scan_requests(
        scan_id, module=module, status_code=status_code, limit=limit, offset=offset
    )
    total = await get_scan_request_count(scan_id)

    return JSONResponse(content={
        "total": total,
        "offset": offset,
        "limit": limit,
        "requests": [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "method": r.method,
                "url": r.url,
                "status_code": r.status_code,
                "duration_ms": r.duration_ms,
                "module": r.module,
                "finding_id": r.finding_id,
                "request_headers": r.request_headers,
                "request_body": r.request_body,
                "response_headers": r.response_headers,
                "response_body": r.response_body,
            }
            for r in requests
        ],
    })


@app.get("/scan/{scan_id}/events/json")
async def scan_events_json(scan_id: int):
    """scan diagnostic events for the Diagnostics tab."""
    from parascan.core.state import get_scan_events

    events = await get_scan_events(scan_id)
    return JSONResponse(content={
        "total": len(events),
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "level": e.level,
                "category": e.category,
                "message": e.message,
                "detail": e.detail,
            }
            for e in events
        ],
    })


@app.get("/scan/{scan_id}/compliance", response_class=HTMLResponse)
async def scan_compliance(scan_id: int):
    """redirect to unified report for backward compatibility."""
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url=f"/scan/{scan_id}/report")
