import uuid
import asyncio
from datetime import datetime
from typing import Optional, List
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func, and_
from sqlalchemy.orm import selectinload

from backend.database import get_db, async_session
from backend.models import Scan, Finding, AttackSurface, Report
from backend.config import settings
from backend.engine.orchestrator import run_scan
from backend import memory_store

router = APIRouter(prefix="/api/scans", tags=["scans"])

active_tasks: dict[str, asyncio.Task] = {}

active_scans: dict[str, asyncio.Event] = {}
active_stop_events: dict[str, asyncio.Event] = {}


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    paused = "paused"
    completed = "completed"
    failed = "failed"
    stopped = "stopped"
    cancelled = "cancelled"


class SeverityLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ScanConfig(BaseModel):
    max_depth: int = Field(default=5, ge=1, le=50)
    concurrency: int = Field(default=10, ge=1, le=100)
    rate_limit: int = Field(default=30, ge=1, le=500)
    tools: List[str] = Field(default_factory=lambda: [
        "crawler", "nuclei", "ffuf", "sqlmap"
    ])
    follow_redirects: bool = True
    verify_ssl: bool = False
    custom_headers: dict = Field(default_factory=dict)
    excluded_paths: List[str] = Field(default_factory=list)
    scope_regex: str = ""


class ScanCreate(BaseModel):
    target_url: str = Field(..., max_length=2048)
    config: ScanConfig = Field(default_factory=ScanConfig)


class ScanUpdate(BaseModel):
    target_url: Optional[str] = Field(None, max_length=2048)
    config: Optional[ScanConfig] = None


class ToolStatus(BaseModel):
    name: str
    status: str
    progress: float = 0.0
    current_action: str = ""
    findings_count: int = 0
    started_at: Optional[str] = None
    error: Optional[str] = None


class ScanSummary(BaseModel):
    id: str
    target_url: str
    status: str
    created_at: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0


class ScanDetail(BaseModel):
    id: str
    target_url: str
    status: str
    config: dict
    created_at: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    elapsed_seconds: Optional[float] = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    progress: float = 0.0
    current_phase: str = ""


class FindingSummary(BaseModel):
    id: str
    title: str
    severity: str
    cvss_score: float
    confidence: str
    vulnerability_id: str
    cwe_id: str
    injection_family: str
    injection_subtype: str
    affected_url: str
    affected_parameter: str
    verified: bool
    created_at: str


class FindingDetail(BaseModel):
    id: str
    scan_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    confidence: str
    vulnerability_id: str
    cwe_id: str
    injection_family: str
    injection_subtype: str
    affected_url: str
    affected_parameter: str
    http_method: str
    parameter_location: str
    payload: str
    request_data: dict
    response_data: dict
    baseline_request: dict
    baseline_response: dict
    evidence_json: dict
    mitigation_text: str
    references_json: list
    verified: bool
    created_at: str


class AttackSurfaceItem(BaseModel):
    id: str
    url: str
    http_method: str
    parameters_json: list
    form_fields_json: list
    headers_json: dict
    technology_json: dict
    element_type: str
    source_tool: str
    created_at: str


class AttackSurfaceResponse(BaseModel):
    scan_id: str
    total_endpoints: int
    urls: List[AttackSurfaceItem]


class ToolsStatusResponse(BaseModel):
    scan_id: str
    tools: List[ToolStatus]


class ScanActionResponse(BaseModel):
    scan_id: str
    status: str
    message: str


def serialize_uuid(val) -> str:
    if val is None:
        return ""
    if isinstance(val, uuid.UUID):
        return str(val)
    return str(val)


def serialize_datetime(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


def _mem_scan_to_detail(rec: dict, findings_count: Optional[int] = None) -> ScanDetail:
    counts = rec.get("severity_counts") or {}
    fc = findings_count if findings_count is not None else rec.get("findings_count", 0)
    elapsed = None
    start = rec.get("start_time")
    if start:
        try:
            start_dt = start if isinstance(start, datetime) else datetime.fromisoformat(str(start))
            end = rec.get("end_time")
            end_dt = end if isinstance(end, datetime) else (
                datetime.fromisoformat(str(end)) if end else datetime.utcnow()
            )
            elapsed = (end_dt - start_dt).total_seconds()
        except Exception:
            elapsed = None
    progress = 0.0
    phase = rec.get("current_phase", "") or ""
    status = rec.get("status", "")
    if status == "completed":
        progress = 100.0
    elif status == "running":
        progress = 25.0
    return ScanDetail(
        id=rec.get("id", ""),
        target_url=rec.get("target_url", ""),
        status=status,
        config=rec.get("config", {}) or {},
        created_at=serialize_datetime(rec.get("created_at")),
        start_time=serialize_datetime(rec.get("start_time")),
        end_time=serialize_datetime(rec.get("end_time")),
        elapsed_seconds=elapsed,
        findings_count=fc,
        critical_count=counts.get("critical", 0),
        high_count=counts.get("high", 0),
        medium_count=counts.get("medium", 0),
        low_count=counts.get("low", 0),
        info_count=counts.get("info", 0),
        progress=progress,
        current_phase=phase,
    )


def _mem_finding_to_detail(f: dict, scan_id: str) -> FindingDetail:
    return FindingDetail(
        id=f.get("id", "") or str(uuid.uuid4()),
        scan_id=scan_id,
        title=f.get("title", "Untitled finding"),
        description=f.get("description", ""),
        severity=f.get("severity", "info"),
        cvss_score=f.get("cvss_score", 0.0),
        cvss_vector=f.get("cvss_vector", ""),
        confidence=f.get("confidence", "low"),
        vulnerability_id=f.get("vulnerability_id", ""),
        cwe_id=f.get("cwe_id", ""),
        injection_family=f.get("injection_family", ""),
        injection_subtype=f.get("injection_subtype", ""),
        affected_url=f.get("affected_url", ""),
        affected_parameter=f.get("affected_parameter", ""),
        http_method=f.get("http_method", "") or f.get("evidence", {}).get("http_method", ""),
        parameter_location=f.get("parameter_location", "") or f.get("evidence", {}).get("parameter_location", ""),
        payload=f.get("payload", ""),
        request_data=f.get("request", {}) or {},
        response_data=f.get("response", {}) or {},
        baseline_request=f.get("baseline_request", {}) or {},
        baseline_response=f.get("baseline_response", {}) or {},
        evidence_json=f.get("evidence", {}) or {},
        mitigation_text=f.get("remediation", ""),
        references_json=f.get("references", []) or [],
        verified=bool(f.get("verified", False)),
        created_at=serialize_datetime(f.get("created_at")) or datetime.utcnow().isoformat(),
    )


async def _fetch_scan_row(db: AsyncSession, scan_uuid: uuid.UUID) -> Optional[Scan]:
    """Fetch the Scan row, returning None instead of raising when the DB is down."""
    try:
        result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
        return result.scalar_one_or_none()
    except Exception:
        return None


async def _run_scan_background(scan_id: str, config: dict):
    pause_event = asyncio.Event()
    pause_event.set()
    active_scans[str(scan_id)] = pause_event

    stop_event = asyncio.Event()
    active_stop_events[str(scan_id)] = stop_event

    config = dict(config or {})
    mem_record = memory_store.get_scan(str(scan_id)) or {}
    config.setdefault("target_url", mem_record.get("target_url", ""))

    db = None
    try:
        try:
            db = async_session()
            scan = await _fetch_scan_row(db, uuid.UUID(scan_id))
            if scan:
                scan.status = "running"
                scan.start_time = datetime.utcnow()
                if scan.target_url:
                    config["target_url"] = scan.target_url
                await db.commit()
        except Exception:
            pass  # DB unavailable — scan continues in memory mode

        memory_store.upsert_scan(
            str(scan_id),
            status="running",
            start_time=datetime.utcnow().isoformat(),
        )
        # global watchdog: a scan must always reach a terminal state —
        # cap total runtime so it can never hang in "running" forever
        try:
            await asyncio.wait_for(
                run_scan(
                    scan_id=scan_id,
                    config=config,
                    stop_event=stop_event,
                ),
                timeout=45 * 60,
            )
        except asyncio.TimeoutError:
            memory_store.set_scan_status(
                str(scan_id), "failed",
                extra={"error_message": "Scan exceeded the 45-minute global time limit and was aborted"},
            )
            from backend.api.websocket import emit_scan_error
            await emit_scan_error(str(scan_id), "Scan exceeded the 45-minute global time limit and was aborted")
            return

    except asyncio.CancelledError:
        memory_store.set_scan_status(str(scan_id), "stopped")
        try:
            if db is not None:
                cancel_result = await db.execute(
                    select(Scan).where(Scan.id == uuid.UUID(scan_id))
                )
                cancel_scan = cancel_result.scalar_one_or_none()
                if cancel_scan:
                    cancel_scan.status = "stopped"
                    cancel_scan.end_time = datetime.utcnow()
                    await db.commit()
        except Exception:
            pass

    except Exception as e:
        memory_store.set_scan_status(str(scan_id), "failed", extra={"error_message": str(e)})
        try:
            if db is not None:
                err_result = await db.execute(
                    select(Scan).where(Scan.id == uuid.UUID(scan_id))
                )
                err_scan = err_result.scalar_one_or_none()
                if err_scan:
                    err_scan.status = "failed"
                    err_scan.end_time = datetime.utcnow()
                    err_scan.error_message = str(e)[:2000]
                    await db.commit()
        except Exception:
            pass

    finally:
        if db is not None:
            try:
                await db.close()
            except Exception:
                pass
        active_tasks.pop(str(scan_id), None)
        active_scans.pop(str(scan_id), None)
        active_stop_events.pop(str(scan_id), None)


@router.get("", response_model=List[ScanSummary])
async def list_scans(
    status: Optional[ScanStatus] = Query(None, description="Filter by status"),
    start_date: Optional[datetime] = Query(None, description="Filter scans created after this date"),
    end_date: Optional[datetime] = Query(None, description="Filter scans created before this date"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    query = select(Scan).options(selectinload(Scan.findings))

    if status:
        query = query.where(Scan.status == status.value)

    if start_date:
        query = query.where(Scan.created_at >= start_date)

    if end_date:
        query = query.where(Scan.created_at <= end_date)

    query = query.order_by(Scan.created_at.desc())
    query = query.offset(offset).limit(limit)

    summaries = []
    db_ids = set()
    try:
        result = await db.execute(query)
        scans = result.scalars().all()
    except Exception:
        scans = []

    for scan in scans:
        db_ids.add(serialize_uuid(scan.id))
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in scan.findings:
            sev = finding.severity.lower() if finding.severity else "info"
            if sev in severity_counts:
                severity_counts[sev] += 1

        summaries.append(ScanSummary(
            id=serialize_uuid(scan.id),
            target_url=scan.target_url,
            status=scan.status,
            created_at=serialize_datetime(scan.created_at),
            start_time=serialize_datetime(scan.start_time),
            end_time=serialize_datetime(scan.end_time),
            findings_count=len(scan.findings),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            info_count=severity_counts["info"],
        ))

    # include memory-mode scans (DB was down at creation time)
    if not status:
        for rec in memory_store.list_scans():
            if rec.get("id") in db_ids:
                continue
            counts = rec.get("severity_counts") or {}
            summaries.append(ScanSummary(
                id=rec.get("id", ""),
                target_url=rec.get("target_url", ""),
                status=rec.get("status", ""),
                created_at=serialize_datetime(rec.get("created_at")),
                start_time=serialize_datetime(rec.get("start_time")),
                end_time=serialize_datetime(rec.get("end_time")),
                findings_count=rec.get("findings_count", 0),
                critical_count=counts.get("critical", 0),
                high_count=counts.get("high", 0),
                medium_count=counts.get("medium", 0),
                low_count=counts.get("low", 0),
                info_count=counts.get("info", 0),
            ))

    return summaries[:limit]


@router.post("", response_model=ScanDetail, status_code=201)
async def create_scan(
    scan_data: ScanCreate,
    db: AsyncSession = Depends(get_db),
):
    scan_id = str(uuid.uuid4())

    try:
        new_scan = Scan(
            id=uuid.UUID(scan_id),
            target_url=scan_data.target_url,
            status="pending",
            config_json=scan_data.config.model_dump(),
            created_at=datetime.utcnow(),
        )
        db.add(new_scan)
        await db.commit()
        await db.refresh(new_scan)

        return ScanDetail(
            id=serialize_uuid(new_scan.id),
            target_url=new_scan.target_url,
            status=new_scan.status,
            config=new_scan.config_json or {},
            created_at=serialize_datetime(new_scan.created_at),
            start_time=serialize_datetime(new_scan.start_time),
            end_time=serialize_datetime(new_scan.end_time),
            elapsed_seconds=None,
            findings_count=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            info_count=0,
            progress=0.0,
            current_phase="",
        )
    except Exception as e:
        import traceback
        error_msg = traceback.format_exc()
        # PostgreSQL unreachable — register the scan in memory so it can run
        if db is not None:
            try:
                await db.rollback()
            except Exception:
                pass
        
        try:
            record = memory_store.upsert_scan(
                scan_id,
                target_url=scan_data.target_url,
                status="pending",
                config=scan_data.config.model_dump(),
                created_at=datetime.utcnow().isoformat(),
            )
            return _mem_scan_to_detail(record)
        except Exception as memory_err:
            raise HTTPException(status_code=500, detail=f"DB Error: {error_msg}\nMemory Error: {str(memory_err)}")


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan = await _fetch_scan_row_with_findings(db, scan_uuid)
    if scan:
        return _detail_from_row(scan)

    record = memory_store.get_scan(scan_id)
    if record:
        return _mem_scan_to_detail(record)

    raise HTTPException(status_code=404, detail="Scan not found")


def _detail_from_row(scan: Scan) -> ScanDetail:
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in scan.findings:
        sev = finding.severity.lower() if finding.severity else "info"
        if sev in severity_counts:
            severity_counts[sev] += 1

    elapsed = None
    if scan.start_time:
        end = scan.end_time or datetime.utcnow()
        elapsed = (end - scan.start_time).total_seconds()

    progress = 0.0
    current_phase = scan.current_phase or ""
    if scan.status == "running":
        progress = 25.0
    elif scan.status == "completed":
        progress = 100.0
    elif scan.status == "pending":
        current_phase = current_phase or "Queued"

    return ScanDetail(
        id=serialize_uuid(scan.id),
        target_url=scan.target_url,
        status=scan.status,
        config=scan.config_json or {},
        created_at=serialize_datetime(scan.created_at),
        start_time=serialize_datetime(scan.start_time),
        end_time=serialize_datetime(scan.end_time),
        elapsed_seconds=elapsed,
        findings_count=len(scan.findings),
        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
        medium_count=severity_counts["medium"],
        low_count=severity_counts["low"],
        info_count=severity_counts["info"],
        progress=progress,
        current_phase=current_phase,
    )


async def _fetch_scan_row_with_findings(db: AsyncSession, scan_uuid: uuid.UUID) -> Optional[Scan]:
    try:
        result = await db.execute(
            select(Scan)
            .options(selectinload(Scan.findings))
            .where(Scan.id == scan_uuid)
        )
        return result.scalar_one_or_none()
    except Exception:
        return None


@router.post("/{scan_id}/start", response_model=ScanActionResponse)
async def start_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan = await _fetch_scan_row(db, scan_uuid)
    mem_record = memory_store.get_scan(scan_id)

    if not scan and not mem_record:
        raise HTTPException(status_code=404, detail="Scan not found")

    current_status = scan.status if scan else mem_record.get("status", "")
    if current_status == "running":
        raise HTTPException(status_code=409, detail="Scan is already running")

    if scan_id in active_tasks:
        raise HTTPException(status_code=409, detail="Scan task is already active")

    config = dict((scan.config_json if scan else mem_record.get("config")) or {})
    config["target_url"] = scan.target_url if scan else mem_record.get("target_url", "")
    
    task = asyncio.create_task(_run_scan_background(scan_id, config))
    active_tasks[scan_id] = task

    return ScanActionResponse(
        scan_id=scan_id,
        status="running",
        message="Scan execution started",
    )


@router.post("/{scan_id}/stop", response_model=ScanActionResponse)
async def stop_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan = await _fetch_scan_row(db, scan_uuid)
    mem_record = memory_store.get_scan(scan_id)

    if not scan and not mem_record:
        raise HTTPException(status_code=404, detail="Scan not found")

    current_status = scan.status if scan else mem_record.get("status", "")
    if current_status not in ("running", "paused"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot stop scan in '{current_status}' status",
        )

    task = active_tasks.pop(scan_id, None)
    stop_ev = active_stop_events.get(scan_id)
    pause_ev = active_scans.get(scan_id)

    if stop_ev:
        stop_ev.set()
    elif task and not task.done():
        task.cancel()
        
    if pause_ev:
        pause_ev.set()

    active_scans.pop(scan_id, None)
    active_stop_events.pop(scan_id, None)

    if scan:
        scan.status = "stopped"
        scan.end_time = datetime.utcnow()
        try:
            await db.commit()
        except Exception:
            await db.rollback()
    memory_store.set_scan_status(scan_id, "stopped")

    return ScanActionResponse(
        scan_id=scan_id,
        status="stopped",
        message="Scan stopped",
    )


@router.delete("/clear-all", status_code=200)
async def clear_all_scans(
    db: AsyncSession = Depends(get_db),
):
    """Delete every scan (and its findings/surfaces/reports) from memory
    and, when reachable, PostgreSQL. Running scans are cancelled first."""
    cancelled = 0
    for scan_id, task in list(active_tasks.items()):
        if task and not task.done():
            task.cancel()
            cancelled += 1
        active_scans.pop(scan_id, None)
        active_stop_events.pop(scan_id, None)
    active_tasks.clear()

    removed_pg = 0
    try:
        result = await db.execute(select(Scan))
        rows = list(result.scalars().all())
        removed_pg = len(rows)
        for row in rows:
            await db.execute(delete(Finding).where(Finding.scan_id == row.id))
            await db.execute(delete(AttackSurface).where(AttackSurface.scan_id == row.id))
            await db.execute(delete(Report).where(Report.scan_id == row.id))
        await db.execute(delete(Scan))
        await db.commit()
    except Exception:
        await db.rollback()

    removed_mem = memory_store.clear_all()
    return {"deleted": max(removed_pg, removed_mem), "cancelled_running": cancelled}


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan = await _fetch_scan_row(db, scan_uuid)
    mem_record = memory_store.get_scan(scan_id)

    if not scan and not mem_record:
        raise HTTPException(status_code=404, detail="Scan not found")

    current_status = scan.status if scan else mem_record.get("status", "")
    if current_status == "running":
        task = active_tasks.pop(scan_id, None)
        if task and not task.done():
            task.cancel()
        active_scans.pop(scan_id, None)
        active_stop_events.pop(scan_id, None)

    try:
        await db.execute(
            delete(Finding).where(Finding.scan_id == scan_uuid)
        )
        await db.execute(
            delete(AttackSurface).where(AttackSurface.scan_id == scan_uuid)
        )
        await db.execute(
            delete(Report).where(Report.scan_id == scan_uuid)
        )
        await db.execute(
            delete(Scan).where(Scan.id == scan_uuid)
        )
        await db.commit()
    except Exception:
        await db.rollback()

    memory_store.delete_scan(scan_id)


@router.get("/{scan_id}/findings", response_model=List[FindingDetail])
async def get_scan_findings(
    scan_id: str,
    severity: Optional[SeverityLevel] = Query(None, description="Filter by severity"),
    verified_only: bool = Query(False, description="Only return verified findings"),
    limit: int = Query(500, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan_check = await _fetch_scan_row(db, scan_uuid)
    if not scan_check and not memory_store.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    query = select(Finding).where(Finding.scan_id == scan_uuid)

    if severity:
        query = query.where(Finding.severity == severity.value)

    if verified_only:
        query = query.where(Finding.verified == True)

    from sqlalchemy import case as sql_case
    query = query.order_by(
        sql_case(
            (Finding.severity == "critical", 0),
            (Finding.severity == "high", 1),
            (Finding.severity == "medium", 2),
            (Finding.severity == "low", 3),
            else_=4,
        )
    )
    query = query.offset(offset).limit(limit)

    try:
        result = await db.execute(query)
        findings = result.scalars().all()
        if findings or scan_check is not None:
            return [
                FindingDetail(
                    id=serialize_uuid(f.id),
                    scan_id=serialize_uuid(f.scan_id),
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    cvss_score=f.cvss_score,
                    cvss_vector=f.cvss_vector,
                    confidence=f.confidence,
                    vulnerability_id=f.vulnerability_id,
                    cwe_id=f.cwe_id,
                    injection_family=f.injection_family,
                    injection_subtype=f.injection_subtype,
                    affected_url=f.affected_url,
                    affected_parameter=f.affected_parameter,
                    http_method=getattr(f, "http_method", "") or (f.evidence_json or {}).get("http_method", ""),
                    parameter_location=getattr(f, "parameter_location", "") or (f.evidence_json or {}).get("parameter_location", ""),
                    payload=f.payload,
                    request_data=f.request_data or {},
                    response_data=f.response_data or {},
                    baseline_request=f.baseline_request or {},
                    baseline_response=f.baseline_response or {},
                    evidence_json=f.evidence_json or {},
                    mitigation_text=f.mitigation_text,
                    references_json=f.references_json or [],
                    verified=f.verified,
                    created_at=serialize_datetime(f.created_at),
                )
                for f in findings
            ]
    except Exception:
        pass

    # memory fallback (PostgreSQL down or scan stored in memory only)
    mem_findings = memory_store.get_findings(scan_id)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    mem_findings.sort(key=lambda f: sev_order.get(str(f.get("severity", "info")).lower(), 4))
    if severity:
        mem_findings = [f for f in mem_findings if f.get("severity") == severity.value]
    if verified_only:
        mem_findings = [f for f in mem_findings if f.get("verified")]
    return [_mem_finding_to_detail(f, scan_id) for f in mem_findings[offset:offset + limit]]


@router.get("/{scan_id}/findings/{finding_id}", response_model=FindingDetail)
async def get_finding_detail(
    scan_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    try:
        scan_uuid = uuid.UUID(scan_id)
        finding_uuid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid ID format")

    result = await db.execute(
        select(Finding).where(
            and_(
                Finding.id == finding_uuid,
                Finding.scan_id == scan_uuid,
            )
        )
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingDetail(
        id=serialize_uuid(finding.id),
        scan_id=serialize_uuid(finding.scan_id),
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        cvss_score=finding.cvss_score,
        cvss_vector=finding.cvss_vector,
        confidence=finding.confidence,
        vulnerability_id=finding.vulnerability_id,
        cwe_id=finding.cwe_id,
        injection_family=finding.injection_family,
        injection_subtype=finding.injection_subtype,
        affected_url=finding.affected_url,
        affected_parameter=finding.affected_parameter,
        http_method=getattr(finding, "http_method", "") or (finding.evidence_json or {}).get("http_method", ""),
        parameter_location=getattr(finding, "parameter_location", "") or (finding.evidence_json or {}).get("parameter_location", ""),
        payload=finding.payload,
        request_data=finding.request_data or {},
        response_data=finding.response_data or {},
        baseline_request=finding.baseline_request or {},
        baseline_response=finding.baseline_response or {},
        evidence_json=finding.evidence_json or {},
        mitigation_text=finding.mitigation_text,
        references_json=finding.references_json or [],
        verified=finding.verified,
        created_at=serialize_datetime(finding.created_at),
    )


@router.get("/{scan_id}/attack-surface", response_model=AttackSurfaceResponse)
async def get_attack_surface(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan_check = await _fetch_scan_row(db, scan_uuid)
    if not scan_check and not memory_store.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        result = await db.execute(
            select(AttackSurface)
            .where(AttackSurface.scan_id == scan_uuid)
            .order_by(AttackSurface.created_at.desc())
        )
        surfaces = result.scalars().all()
        if surfaces or scan_check is not None:
            items = [
                AttackSurfaceItem(
                    id=serialize_uuid(s.id),
                    url=s.url,
                    http_method=s.http_method,
                    parameters_json=s.parameters_json or [],
                    form_fields_json=s.form_fields_json or [],
                    headers_json=s.headers_json or {},
                    technology_json=s.technology_json or {},
                    element_type=s.element_type,
                    source_tool=s.source_tool,
                    created_at=serialize_datetime(s.created_at),
                )
                for s in surfaces
            ]
            return AttackSurfaceResponse(
                scan_id=scan_id,
                total_endpoints=len(items),
                urls=items,
            )
    except Exception:
        pass

    # memory fallback
    items = [
        AttackSurfaceItem(
            id=f"{scan_id}-ep-{i}",
            url=ep.get("url", ""),
            http_method=ep.get("method", "GET"),
            parameters_json=ep.get("parameters", []) or [],
            form_fields_json=[],
            headers_json={},
            technology_json={},
            element_type=ep.get("element_type", "url"),
            source_tool=ep.get("source_tool", "crawler"),
            created_at=serialize_datetime(None) or datetime.utcnow().isoformat(),
        )
        for i, ep in enumerate(memory_store.get_surface(scan_id))
    ]
    return AttackSurfaceResponse(
        scan_id=scan_id,
        total_endpoints=len(items),
        urls=items,
    )


@router.get("/{scan_id}/tools/status", response_model=ToolsStatusResponse)
async def get_tools_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan = await _fetch_scan_row(db, scan_uuid)
    mem_record = memory_store.get_scan(scan_id)

    if not scan and not mem_record:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_status = scan.status if scan else mem_record.get("status", "pending")
    config = (scan.config_json if scan else mem_record.get("config")) or {}

    tool_names = ["crawler", "nuclei", "ffuf", "sqlmap"]
    enabled_tools = config.get("tools", tool_names)

    tool_statuses = []
    for name in tool_names:
        if name not in enabled_tools:
            tool_statuses.append(ToolStatus(
                name=name,
                status="disabled",
                progress=0.0,
                current_action="Not enabled in scan config",
                findings_count=0,
                started_at=None,
                error=None,
            ))
            continue

        if scan_status == "running":
            tool_status = "running"
            progress = 50.0
            action = f"Executing {name}"
        elif scan_status == "completed":
            tool_status = "completed"
            progress = 100.0
            action = "Finished"
        elif scan_status in ("paused", "stopped"):
            tool_status = scan_status
            progress = 0.0
            action = f"Scan {scan_status}"
        else:
            tool_status = "pending"
            progress = 0.0
            action = "Waiting to start"

        tool_statuses.append(ToolStatus(
            name=name,
            status=tool_status,
            progress=progress,
            current_action=action,
            findings_count=0,
            started_at=serialize_datetime(scan.start_time if scan else mem_record.get("start_time")),
            error=None,
        ))

    return ToolsStatusResponse(
        scan_id=serialize_uuid(scan_uuid),
        tools=tool_statuses,
    )
