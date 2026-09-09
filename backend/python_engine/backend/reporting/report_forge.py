"""
Report Forge - Main report orchestrator.

Given a scan_id and output format, generates a complete vulnerability report with:
Executive Summary, Scan Metadata, Vulnerability Findings, Mitigation Section,
Compliance Mapping, and Appendix.
"""

import os
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from io import BytesIO

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import async_session
from backend.models import Scan, Finding, Report
from backend.config import settings
from backend.reporting.compliance_mapper import build_compliance_summary, get_all_mappings
from backend.reporting.mitigation_db import get_mitigation, build_mitigation_section

logger = logging.getLogger(__name__)

REPORT_OUTPUT_DIR = os.path.join(settings.BASE_DIR, "reports")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = (f.severity or "info").lower()
        counts[key] = counts.get(key, 0) + 1
    return counts


def _sorted_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get((f.severity or "info").lower(), 99))


async def _fetch_scan_data(scan_id: str, db: AsyncSession) -> Optional[Dict[str, Any]]:
    """Fetch scan and all related findings from the database."""
    scan_uuid = uuid.UUID(scan_id) if isinstance(scan_id, str) else scan_id
    result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
    scan = result.scalar_one_or_none()
    if scan is None:
        logger.error("Scan %s not found", scan_id)
        return None

    finding_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_uuid)
    )
    findings = list(finding_result.scalars().all())
    sorted_findings = _sorted_findings(findings)
    severity_counts = _severity_counts(findings)

    families = list({f.injection_family for f in findings if f.injection_family})
    compliance = build_compliance_summary(families)

    mitigation_items = []
    seen_subtypes = set()
    for f in findings:
        sub_type = f.injection_subtype or ""
        if sub_type and sub_type not in seen_subtypes:
            seen_subtypes.add(sub_type)
            mitigation = get_mitigation(sub_type)
            mitigation_items.append({
                "finding_title": f.title,
                "injection_subtype": sub_type,
                "injection_family": f.injection_family,
                **mitigation,
            })

    scan_config = scan.config_json or {}

    return {
        "scan": scan,
        "findings": sorted_findings,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "families": families,
        "compliance": compliance,
        "mitigation_items": mitigation_items,
        "config": scan_config,
    }


def _build_executive_summary(data: Dict[str, Any]) -> Dict[str, Any]:
    """Build the executive summary section."""
    counts = data["severity_counts"]
    total = data["total_findings"]
    scan = data["scan"]
    duration = None
    if scan.start_time and scan.end_time:
        duration = str(scan.end_time - scan.start_time)

    risk_level = "Low"
    if counts["critical"] > 0:
        risk_level = "Critical"
    elif counts["high"] > 0:
        risk_level = "High"
    elif counts["medium"] > 0:
        risk_level = "Medium"

    return {
        "risk_level": risk_level,
        "total_findings": total,
        "severity_counts": counts,
        "families_detected": data["families"],
        "scan_duration": duration,
        "target_url": scan.target_url,
        "scan_status": scan.status,
        "key_findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "affected_url": f.affected_url,
            }
            for f in data["findings"][:5]
        ],
    }


def _build_scan_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
    """Build the scan metadata section."""
    scan = data["scan"]
    return {
        "scan_id": str(scan.id),
        "target_url": scan.target_url,
        "start_time": scan.start_time.isoformat() if scan.start_time else "N/A",
        "end_time": scan.end_time.isoformat() if scan.end_time else "N/A",
        "status": scan.status,
        "configuration": data["config"],
        "tools_used": data["config"].get("tools", []),
        "total_endpoints": data["config"].get("total_endpoints", 0),
        "total_parameters": data["config"].get("total_parameters", 0),
    }


def _build_finding_details(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Build detailed finding entries."""
    details = []
    for f in findings:
        mitigation = get_mitigation(f.injection_subtype or "")
        compliance = get_all_mappings(f.injection_family or "")
        details.append({
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "confidence": f.confidence,
            "cwe_id": f.cwe_id,
            "vulnerability_id": f.vulnerability_id,
            "injection_family": f.injection_family,
            "injection_subtype": f.injection_subtype,
            "affected_url": f.affected_url,
            "affected_parameter": f.affected_parameter,
            "payload": f.payload,
            "description": f.description,
            "request_data": f.request_data or {},
            "response_data": f.response_data or {},
            "baseline_request": f.baseline_request or {},
            "baseline_response": f.baseline_response or {},
            "evidence_json": f.evidence_json or {},
            "verified": f.verified,
            "mitigation": mitigation,
            "compliance": compliance,
            "references": f.references_json or [],
        })
    return details


async def generate_report(
    scan_id: str,
    output_format: str = "pdf",
    report_title: Optional[str] = None,
    brand_config: Optional[Dict[str, Any]] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a complete report for the given scan.

    Args:
        scan_id: UUID string of the scan to report on.
        output_format: One of 'pdf', 'html', 'csv', 'json', 'nessus'.
        report_title: Optional custom title for the report.
        brand_config: Optional branding configuration (logo, colors, etc.).
        output_path: Optional explicit output file path.

    Returns:
        Dict with report metadata including file_path and format.
    """
    async with async_session() as db:
        data = await _fetch_scan_data(scan_id, db)
        if data is None:
            raise ValueError(f"Scan {scan_id} not found")

        executive_summary = _build_executive_summary(data)
        scan_metadata = _build_scan_metadata(data)
        finding_details = _build_finding_details(data["findings"])

        report_context = {
            "title": report_title or f"Vulnerability Report - {data['scan'].target_url}",
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": executive_summary,
            "scan_metadata": scan_metadata,
            "findings": finding_details,
            "mitigation_items": data["mitigation_items"],
            "compliance": data["compliance"],
            "appendix": {
                "severity_definitions": {
                    "Critical": "Exploitation is straightforward and results in complete system compromise.",
                    "High": "Exploitation requires specific conditions but leads to significant impact.",
                    "Medium": "Exploitation is possible but requires chaining with other vulnerabilities.",
                    "Low": "Limited impact, typically requires authenticated access or specific configurations.",
                    "Info": "Informational finding with no direct security impact.",
                },
                "cvss_scoring": "CVSS v3.1 scores range from 0.0 to 10.0.",
                "tool_versions": data["config"].get("tool_versions", {}),
            },
            "scan_id": scan_id,
            "format": output_format,
        }

        os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

        if output_format == "pdf":
            from backend.reporting.pdf_generator import generate_pdf
            file_path = output_path or os.path.join(
                REPORT_OUTPUT_DIR, f"report_{scan_id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
            )
            await generate_pdf(report_context, file_path, brand_config)

        elif output_format == "html":
            from backend.reporting.html_generator import generate_html
            file_path = output_path or os.path.join(
                REPORT_OUTPUT_DIR, f"report_{scan_id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
            )
            await generate_html(report_context, file_path)

        elif output_format == "csv":
            from backend.reporting.csv_generator import generate_csv
            file_path = output_path or os.path.join(
                REPORT_OUTPUT_DIR, f"report_{scan_id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            await generate_csv(report_context, file_path)

        elif output_format == "json":
            from backend.reporting.json_generator import generate_json
            file_path = output_path or os.path.join(
                REPORT_OUTPUT_DIR, f"report_{scan_id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            )
            await generate_json(report_context, file_path)

        elif output_format == "nessus":
            from backend.reporting.nessus_generator import generate_nessus
            file_path = output_path or os.path.join(
                REPORT_OUTPUT_DIR, f"report_{scan_id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.nessus"
            )
            await generate_nessus(report_context, file_path)

        else:
            raise ValueError(f"Unsupported report format: {output_format}")

        report_record = Report(
            scan_id=uuid.UUID(scan_id) if isinstance(scan_id, str) else scan_id,
            title=report_context["title"],
            format=output_format,
            config_json=brand_config or {},
            file_path=file_path,
        )
        db.add(report_record)
        await db.commit()

        logger.info("Report generated: %s (%s)", file_path, output_format)

        return {
            "report_id": str(report_record.id),
            "scan_id": scan_id,
            "format": output_format,
            "file_path": file_path,
            "title": report_context["title"],
            "generated_at": report_context["generated_at"],
            "total_findings": data["total_findings"],
            "severity_counts": data["severity_counts"],
        }
