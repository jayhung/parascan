"""scan state persistence and resume backed by SQLite."""

from __future__ import annotations

import datetime

from sqlalchemy import select, update

from parascan.core.db import Endpoint, Finding, Scan, ScanStatus, get_session


async def create_scan(target_url: str, config_json: dict | None = None) -> int:
    """create a new scan record and return its id."""
    session = await get_session()
    async with session.begin():
        scan = Scan(
            target_url=target_url,
            status=ScanStatus.RUNNING.value,
            config_json=config_json,
        )
        session.add(scan)
        await session.flush()
        scan_id = scan.id
    await session.close()
    return scan_id


async def finish_scan(scan_id: int, status: ScanStatus = ScanStatus.COMPLETED) -> None:
    """mark a scan as completed or failed."""
    session = await get_session()
    async with session.begin():
        await session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(status=status.value, finished_at=datetime.datetime.now(datetime.UTC))
        )
    await session.close()


async def update_scan_progress(scan_id: int, total: int, scanned: int) -> None:
    """update scan progress counters."""
    session = await get_session()
    async with session.begin():
        await session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(total_endpoints=total, scanned_endpoints=scanned)
        )
    await session.close()


async def update_scan_fingerprint(scan_id: int, fingerprint: str) -> None:
    """store fingerprint data on the scan record."""
    session = await get_session()
    async with session.begin():
        await session.execute(
            update(Scan).where(Scan.id == scan_id).values(fingerprint=fingerprint)
        )
    await session.close()


async def save_endpoints(scan_id: int, endpoints: list[dict]) -> list[int]:
    """save discovered endpoints and return their ids."""
    session = await get_session()
    ids = []
    async with session.begin():
        for ep in endpoints:
            endpoint = Endpoint(
                scan_id=scan_id,
                url=ep["url"],
                method=ep.get("method", "GET"),
                params=ep.get("params"),
            )
            session.add(endpoint)
            await session.flush()
            ids.append(endpoint.id)
    await session.close()
    return ids


async def mark_endpoint_scanned(endpoint_id: int) -> None:
    """mark an endpoint as scanned."""
    session = await get_session()
    async with session.begin():
        await session.execute(
            update(Endpoint).where(Endpoint.id == endpoint_id).values(scanned=1)
        )
    await session.close()


async def save_finding(
    scan_id: int,
    endpoint_id: int | None,
    module: str,
    severity: str,
    title: str,
    description: str,
    evidence: str | None = None,
    request_data: str | None = None,
    response_data: str | None = None,
    remediation: str | None = None,
    soc2_criteria: str | None = None,
    retest_status: str | None = None,
) -> int:
    """save a finding and return its id."""
    session = await get_session()
    async with session.begin():
        finding = Finding(
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            module=module,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            request_data=request_data,
            response_data=response_data,
            remediation=remediation,
            soc2_criteria=soc2_criteria,
            retest_status=retest_status,
        )
        session.add(finding)
        await session.flush()
        finding_id = finding.id
    await session.close()
    return finding_id


async def get_unscanned_endpoints(scan_id: int) -> list[Endpoint]:
    """get all unscanned endpoints for a scan (for resume)."""
    session = await get_session()
    result = await session.execute(
        select(Endpoint).where(Endpoint.scan_id == scan_id, Endpoint.scanned == 0)
    )
    endpoints = list(result.scalars().all())
    await session.close()
    return endpoints


async def get_latest_scan() -> Scan | None:
    """get the most recent scan record."""
    session = await get_session()
    result = await session.execute(
        select(Scan).order_by(Scan.id.desc()).limit(1)
    )
    scan = result.scalar_one_or_none()
    await session.close()
    return scan


async def get_all_scans() -> list[Scan]:
    """get all scan records ordered by most recent first."""
    session = await get_session()
    result = await session.execute(select(Scan).order_by(Scan.id.desc()))
    scans = list(result.scalars().all())
    await session.close()
    return scans


async def get_findings_for_scan(scan_id: int) -> list[Finding]:
    """get all findings for a scan."""
    session = await get_session()
    result = await session.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
    )
    findings = list(result.scalars().all())
    await session.close()
    return findings
