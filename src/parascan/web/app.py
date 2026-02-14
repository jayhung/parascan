"""FastAPI web dashboard for browsing scan results."""

from __future__ import annotations

import pathlib

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="parascan dashboard")

TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
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
    from parascan.core.reporter import SOC2_CRITERIA_DESCRIPTIONS
    criteria_grouped: dict[str, list] = {}
    for f in findings:
        if f.soc2_criteria:
            criteria_grouped.setdefault(f.soc2_criteria, []).append(f)

    return templates.TemplateResponse("scan.html", {
        "request": request,
        "scan": scan,
        "findings": findings,
        "grouped": grouped,
        "by_module": by_module,
        "total": len(findings),
        "soc2_criteria": SOC2_CRITERIA_DESCRIPTIONS,
        "criteria_grouped": criteria_grouped,
    })


@app.get("/scan/{scan_id}/json")
async def scan_json(scan_id: int):
    """JSON export endpoint."""
    from parascan.core.reporter import generate_json_report
    import json

    report = await generate_json_report(scan_id)
    return JSONResponse(content=json.loads(report))


@app.get("/scan/{scan_id}/report", response_class=HTMLResponse)
async def scan_report(scan_id: int):
    """unified HTML report (includes SOC 2 compliance)."""
    from parascan.core.reporter import generate_html_report

    return HTMLResponse(await generate_html_report(scan_id))


@app.get("/scan/{scan_id}/compliance", response_class=HTMLResponse)
async def scan_compliance(scan_id: int):
    """redirect to unified report for backward compatibility."""
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url=f"/scan/{scan_id}/report")
