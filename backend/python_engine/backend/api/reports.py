import os
import uuid
import asyncio
import json
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.database import get_db, async_session
from backend.models import Report, Scan
from backend.reporting.report_forge import generate_report

router = APIRouter(prefix="/api/reports", tags=["reports"])

active_report_tasks: dict[str, asyncio.Task] = {}

REPORT_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)


def serialize_uuid(val) -> str:
    if val is None:
        return ""
    if isinstance(val, uuid.UUID):
        return str(val)
    return str(val)


class ReportGenerateRequest(BaseModel):
    scan_id: str = Field(..., description="UUID of the scan to generate a report for")
    format: str = Field(default="json", description="Report format: pdf, json, html, markdown")
    options: dict = Field(default_factory=dict, description="Additional report generation options")


class ReportActionResponse(BaseModel):
    report_id: str
    status: str
    message: str
    download_url: Optional[str] = None


def _build_report_from_memory(scan_id: str, fmt: str) -> dict:
    """Build a report entirely from memory_store (no PG needed)."""
    from backend import memory_store
    from backend.reporting.mitigation_db import MitigationDB
    from backend.reporting.compliance_mapper import build_compliance_summary

    scan = memory_store.get_scan(scan_id)
    if not scan:
        return None

    findings = memory_store.get_findings(scan_id) or []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 99))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        k = (f.get("severity") or "info").lower()
        severity_counts[k] = severity_counts.get(k, 0) + 1

    total = len(findings)
    risk = "Low"
    if severity_counts["critical"] > 0:
        risk = "Critical"
    elif severity_counts["high"] > 0:
        risk = "High"
    elif severity_counts["medium"] > 0:
        risk = "Medium"

    families = list({f.get("injection_family", "") for f in findings if f.get("injection_family")})

    mit_db = MitigationDB()
    mitigation_items = []
    seen_sub = set()
    for f in findings:
        sub = f.get("injection_subtype", "") or ""
        if sub and sub not in seen_sub:
            seen_sub.add(sub)
            mit = mit_db.get_mitigation(sub)
            mitigation_items.append({
                "finding_title": f.get("title", ""),
                "injection_subtype": sub,
                "injection_family": f.get("injection_family", ""),
                **mit,
            })

    compliance = build_compliance_summary(families)

    report_data = {
        "scan_id": scan_id,
        "title": f"Vulnerability Report - {scan.get('target_url', 'unknown')}",
        "generated_at": datetime.utcnow().isoformat(),
        "target_url": scan.get("target_url", ""),
        "scan_status": scan.get("status", "unknown"),
        "scan_duration": scan.get("scan_duration", 0),
        "risk_level": risk,
        "total_findings": total,
        "severity_counts": severity_counts,
        "families_detected": families,
        "key_findings": [
            {
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "affected_url": f.get("affected_url", ""),
                "affected_parameter": f.get("affected_parameter", ""),
            }
            for f in findings[:5]
        ],
        "findings": [
            {
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "cvss_score": f.get("cvss_score", 0),
                "cvss_vector": f.get("cvss_vector", ""),
                "confidence": f.get("confidence", "low"),
                "verified": f.get("verified", False),
                "injection_family": f.get("injection_family", ""),
                "injection_subtype": f.get("injection_subtype", ""),
                "cwe_id": f.get("cwe_id", ""),
                "affected_url": f.get("affected_url", ""),
                "affected_parameter": f.get("affected_parameter", ""),
                "payload": f.get("payload", ""),
                "description": f.get("description", ""),
                "evidence": f.get("evidence", {}),
                "remediation": f.get("remediation", ""),
            }
            for f in findings
        ],
        "mitigation_items": mitigation_items,
        "compliance": compliance,
        "config": scan.get("config", {}),
        "appendix": {
            "severity_definitions": {
                "Critical": "Exploitation is straightforward and results in complete system compromise.",
                "High": "Exploitation requires specific conditions but leads to significant impact.",
                "Medium": "Exploitation is possible but requires chaining with other vulnerabilities.",
                "Low": "Limited impact, typically requires authenticated access or specific configurations.",
                "Info": "Informational finding with no direct security impact.",
            },
            "cvss_scoring": "CVSS v3.1 scores range from 0.0 to 10.0.",
        },
    }
    return report_data


def _write_report_file(report_data: dict, fmt: str, scan_id: str) -> str:
    """Write report to disk, return file path."""
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"report_{scan_id[:8]}_{ts}.{fmt}"
    filepath = os.path.join(REPORT_OUTPUT_DIR, filename)
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

    if fmt == "json":
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)
    elif fmt == "html":
        _write_html_report(report_data, filepath)
    elif fmt == "markdown":
        _write_markdown_report(report_data, filepath)
    elif fmt == "pdf":
        _write_html_report(report_data, filepath)  # fallback to HTML if no PDF lib
    else:
        filepath = filepath.replace(f".{fmt}", ".json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)

    return filepath


def _write_html_report(data: dict, filepath: str):
    """Generate a self-contained HTML vulnerability report."""
    severity_colors = {
        "critical": "#dc2626", "high": "#f59e0b",
        "medium": "#3b82f6", "low": "#6b7280", "info": "#9ca3af",
    }
    findings_html = ""
    for f in data.get("findings", []):
        sev = f.get("severity", "info")
        color = severity_colors.get(sev, "#6b7280")
        findings_html += f"""
        <tr>
          <td style="padding:8px;border-bottom:1px solid #e5e7eb;color:{color};font-weight:600;text-transform:uppercase">{sev}</td>
          <td style="padding:8px;border-bottom:1px solid #e5e7eb">{f.get('injection_family','')}/{f.get('injection_subtype','')}</td>
          <td style="padding:8px;border-bottom:1px solid #e5e7eb"><code>{f.get('affected_url','')[:80]}</code></td>
          <td style="padding:8px;border-bottom:1px solid #e5e7eb">{f.get('affected_parameter','')}</td>
          <td style="padding:8px;border-bottom:1px solid #e5e7eb">{f.get('cvss_score',0):.1f}</td>
          <td style="padding:8px;border-bottom:1px solid #e5e7eb">{f.get('confidence','low')}</td>
        </tr>"""

    mitigation_html = ""
    for m in data.get("mitigation_items", []):
        mitigation_html += f"""
        <div style="margin-bottom:16px;padding:12px;background:#f9fafb;border-radius:8px;border-left:3px solid #3b82f6">
          <strong>{m.get('injection_subtype','')}</strong> ({m.get('injection_family','')})<br>
          <p style="margin:4px 0;color:#374151">{m.get('remediation','No remediation available.')[:500]}</p>
        </div>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{data.get('title','Report')}</title></head>
<body style="font-family:system-ui,-apple-system,sans-serif;max-width:1000px;margin:0 auto;padding:32px;color:#111">
<h1 style="border-bottom:2px solid #3b82f6;padding-bottom:8px">{data.get('title','Vulnerability Report')}</h1>

<h2>Executive Summary</h2>
<table style="width:100%;border-collapse:collapse;margin:16px 0">
<tr><td style="padding:8px;background:#f3f4f6;font-weight:600">Risk Level</td><td style="padding:8px;background:#f3f4f6">{data.get('risk_level','N/A')}</td>
<td style="padding:8px;background:#f3f4f6;font-weight:600">Total Findings</td><td style="padding:8px;background:#f3f4f6">{data.get('total_findings',0)}</td></tr>
<tr><td style="padding:8px;font-weight:600">Target</td><td style="padding:8px">{data.get('target_url','')}</td>
<td style="padding:8px;font-weight:600">Scan Duration</td><td style="padding:8px">{data.get('scan_duration',0)}s</td></tr>
</table>

<h3>Severity Distribution</h3>
<ul>{''.join(f'<li>{k.title()}: {v}</li>' for k,v in data.get('severity_counts',{}).items() if v > 0)}</ul>

<h2>Vulnerability Findings</h2>
<table style="width:100%;border-collapse:collapse;margin:16px 0;font-size:13px">
<tr style="background:#f3f4f6"><th style="padding:8px;text-align:left">Severity</th><th style="padding:8px;text-align:left">Type</th><th style="padding:8px;text-align:left">URL</th><th style="padding:8px;text-align:left">Parameter</th><th style="padding:8px;text-align:left">CVSS</th><th style="padding:8px;text-align:left">Confidence</th></tr>
{findings_html}
</table>

<h2>Remediation</h2>
{mitigation_html if mitigation_html else '<p>No specific remediations available.</p>'}

<hr style="margin-top:32px;border:none;border-top:1px solid #e5e7eb">
<p style="font-size:12px;color:#6b7280">Generated by InjectGuard Pro on {data.get('generated_at','')}</p>
</body></html>"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)


def _write_markdown_report(data: dict, filepath: str):
    """Generate a Markdown vulnerability report."""
    lines = [
        f"# {data.get('title', 'Vulnerability Report')}",
        "",
        "## Executive Summary",
        "",
        f"- **Target:** {data.get('target_url', '')}",
        f"- **Risk Level:** {data.get('risk_level', 'N/A')}",
        f"- **Total Findings:** {data.get('total_findings', 0)}",
        f"- **Scan Duration:** {data.get('scan_duration', 0)}s",
        f"- **Generated:** {data.get('generated_at', '')}",
        "",
        "### Severity Distribution",
        "",
    ]
    for sev, count in data.get("severity_counts", {}).items():
        if count > 0:
            lines.append(f"- {sev.title()}: {count}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    lines.append("| Severity | Type | URL | Parameter | CVSS | Confidence |")
    lines.append("|----------|------|-----|-----------|------|------------|")
    for f in data.get("findings", []):
        lines.append(
            f"| {f.get('severity','info')} | {f.get('injection_family','')}/{f.get('injection_subtype','')} "
            f"| `{f.get('affected_url','')[:60]}` | {f.get('affected_parameter','')} "
            f"| {f.get('cvss_score',0):.1f} | {f.get('confidence','low')} |"
        )
    lines.append("")

    lines.append("## Remediation")
    lines.append("")
    for m in data.get("mitigation_items", [])[:20]:
        lines.append(f"### {m.get('injection_subtype', '')} ({m.get('injection_family', '')})")
        lines.append(m.get("remediation", "No remediation available.")[:300])
        lines.append("")

    lines.append("---")
    lines.append(f"*Generated by InjectGuard Pro on {data.get('generated_at', '')}*")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# In-memory report registry (for when PG is down)
_memory_reports: dict[str, dict] = {}


@router.post("/generate", response_model=ReportActionResponse, status_code=202)
async def generate_report_endpoint(
    request: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
):
    scan_id = request.scan_id
    fmt = request.format.lower() if request.format else "json"

    valid_formats = {"pdf", "json", "html", "markdown"}
    if fmt not in valid_formats:
        raise HTTPException(status_code=400, detail=f"Invalid format '{fmt}'. Use: {', '.join(sorted(valid_formats))}")

    # Try PG path
    db_available = False
    scan = None
    try:
        scan_uuid = uuid.UUID(scan_id)
        result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
        scan = result.scalar_one_or_none()
        db_available = True
    except Exception:
        pass

    if db_available and scan:
        # Use the existing report_forge pipeline (PG-backed)
        try:
            report_id = str(uuid.uuid4())
            report_record = Report(
                id=uuid.UUID(report_id),
                scan_id=scan_uuid,
                title=f"Report - {scan.target_url}",
                format=fmt,
                config_json={"status": "generating", "options": request.options},
                file_path="",
                created_at=datetime.utcnow(),
            )
            db.add(report_record)
            await db.commit()

            task = asyncio.create_task(
                _run_pg_report(report_id, str(scan_uuid), fmt, request.options)
            )
            active_report_tasks[report_id] = task

            return ReportActionResponse(
                report_id=report_id,
                status="generating",
                message="Report generation started",
                download_url=f"/api/reports/{report_id}/download",
            )
        except Exception as e:
            # Fall through to memory path
            pass

    # Memory path (no PG needed)
    report_data = _build_report_from_memory(scan_id, fmt)
    if not report_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    filepath = _write_report_file(report_data, fmt, scan_id)
    report_id = str(uuid.uuid4())

    _memory_reports[report_id] = {
        "scan_id": scan_id,
        "format": fmt,
        "file_path": filepath,
        "status": "completed",
        "title": report_data.get("title", "Report"),
        "created_at": datetime.utcnow().isoformat(),
    }

    return ReportActionResponse(
        report_id=report_id,
        status="completed",
        message="Report generated successfully",
        download_url=f"/api/reports/{report_id}/download",
    )


async def _run_pg_report(report_id: str, scan_id: str, fmt: str, options: dict):
    try:
        await generate_report(
            scan_id=scan_id,
            output_format=fmt,
            brand_config=options,
        )
        async with async_session() as db:
            result = await db.execute(select(Report).where(Report.id == uuid.UUID(report_id)))
            report = result.scalar_one_or_none()
            if report:
                report.file_path = f"reports/{report_id}.{fmt}"
                await db.commit()
    except Exception as e:
        async with async_session() as db:
            result = await db.execute(select(Report).where(Report.id == uuid.UUID(report_id)))
            report = result.scalar_one_or_none()
            if report:
                report.config_json = {"status": "failed", "error": str(e), **(report.config_json or {})}
                await db.commit()
    finally:
        active_report_tasks.pop(report_id, None)


@router.get("/list")
async def list_reports():
    """List all available reports (PG + memory)."""
    reports = []
    # Memory-based reports
    for rid, r in _memory_reports.items():
        reports.append({"id": rid, **r})
    # Try PG
    try:
        async with async_session() as db:
            result = await db.execute(select(Report).order_by(Report.created_at.desc()))
            for row in result.scalars().all():
                reports.append({
                    "id": str(row.id),
                    "scan_id": str(row.scan_id),
                    "title": row.title,
                    "format": row.format,
                    "status": (row.config_json or {}).get("status", "unknown"),
                    "created_at": row.created_at.isoformat() if row.created_at else "",
                })
    except Exception:
        pass
    return reports


@router.get("/{report_id}/download")
async def download_report(report_id: str, db: AsyncSession = Depends(get_db)):
    # Check memory registry first
    mem = _memory_reports.get(report_id)
    if mem and mem.get("file_path"):
        if not os.path.isfile(mem["file_path"]):
            raise HTTPException(status_code=404, detail="Report file not found")
        fmt = mem.get("format", "json")
        media_types = {"pdf": "text/html", "json": "application/json", "html": "text/html", "markdown": "text/markdown"}
        filename = f"{mem.get('title', 'report').replace(' ', '_')}.{fmt}"
        return FileResponse(
            path=mem["file_path"],
            filename=filename,
            media_type=media_types.get(fmt, "application/octet-stream"),
        )

    # Fall back to PG
    try:
        report_uuid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID")

    try:
        result = await db.execute(select(Report).where(Report.id == report_uuid))
        report = result.scalar_one_or_none()
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable")

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    config = report.config_json or {}
    status = config.get("status", "")
    if status == "generating":
        raise HTTPException(status_code=202, detail="Report is still being generated")
    if status == "failed":
        raise HTTPException(status_code=500, detail=f"Report generation failed: {config.get('error', 'Unknown')}")
    if not report.file_path or not os.path.isfile(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    format_media_types = {
        "pdf": "application/pdf", "json": "application/json",
        "html": "text/html", "markdown": "text/markdown",
    }
    filename = f"{report.title.replace(' ', '_')}.{report.format}"
    return FileResponse(
        path=report.file_path,
        filename=filename,
        media_type=format_media_types.get(report.format, "application/octet-stream"),
    )
