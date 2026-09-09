"""
JSON Generator - Machine-readable JSON report with full evidence chain.

Produces a structured JSON document containing all scan data, findings,
evidence, mitigations, and compliance mappings.
"""

import os
import json
import logging
from typing import Dict, Any
from datetime import datetime

from backend.config import settings

logger = logging.getLogger(__name__)


def _serialize_value(val: Any) -> Any:
    """Ensure all values are JSON-serializable."""
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    if isinstance(val, dict):
        return {k: _serialize_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_serialize_value(v) for v in val]
    return val


async def generate_json(report_context: Dict[str, Any], output_path: str) -> str:
    """Generate a JSON report from the report context.

    Args:
        report_context: Complete report data dictionary.
        output_path: Path to write the JSON file.

    Returns:
        The output file path.
    """
    findings = report_context.get("findings", [])

    json_findings = []
    for f in findings:
        json_findings.append({
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "cvss_score": f.get("cvss_score", 0.0),
            "cvss_vector": f.get("cvss_vector", ""),
            "confidence": f.get("confidence", ""),
            "cwe_id": f.get("cwe_id", ""),
            "vulnerability_id": f.get("vulnerability_id", ""),
            "injection_family": f.get("injection_family", ""),
            "injection_subtype": f.get("injection_subtype", ""),
            "affected_url": f.get("affected_url", ""),
            "affected_parameter": f.get("affected_parameter", ""),
            "payload": f.get("payload", ""),
            "description": f.get("description", ""),
            "verified": f.get("verified", False),
            "evidence": {
                "request": f.get("request_data", {}),
                "response": f.get("response_data", {}),
                "baseline_request": f.get("baseline_request", {}),
                "baseline_response": f.get("baseline_response", {}),
                "additional_evidence": f.get("evidence_json", {}),
            },
            "mitigation": {
                "title": f.get("mitigation", {}).get("title", ""),
                "description": f.get("mitigation", {}).get("description", ""),
                "remediation": f.get("mitigation", {}).get("remediation", ""),
                "code_examples": f.get("mitigation", {}).get("code_examples", {}),
                "waf_rules": f.get("mitigation", {}).get("waf_rules", {}),
            },
            "compliance": f.get("compliance", {}),
            "references": f.get("references", []) or f.get("mitigation", {}).get("references", []),
        })

    report = {
        "report_metadata": {
            "title": report_context.get("title", ""),
            "generated_at": report_context.get("generated_at", ""),
            "scan_id": report_context.get("scan_id", ""),
            "format": report_context.get("format", "json"),
            "generator": "InjectSentinel Reporting Engine",
            "version": "1.0.0",
        },
        "executive_summary": _serialize_value(report_context.get("executive_summary", {})),
        "scan_metadata": _serialize_value(report_context.get("scan_metadata", {})),
        "findings_summary": {
            "total": len(findings),
            "by_severity": report_context.get("executive_summary", {}).get("severity_counts", {}),
            "families_detected": report_context.get("executive_summary", {}).get("families_detected", []),
        },
        "findings": json_findings,
        "mitigation_reference": _serialize_value(report_context.get("mitigation_items", [])),
        "compliance_mapping": _serialize_value(report_context.get("compliance", {})),
        "appendix": _serialize_value(report_context.get("appendix", {})),
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info("JSON report written to %s (%d findings)", output_path, len(findings))
    return output_path


async def generate_json_bytes(report_context: Dict[str, Any]) -> bytes:
    """Generate a JSON report and return as bytes (for API responses).

    Args:
        report_context: Complete report data dictionary.

    Returns:
        JSON content as bytes.
    """
    findings = report_context.get("findings", [])

    json_findings = []
    for f in findings:
        json_findings.append({
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "cvss_score": f.get("cvss_score", 0.0),
            "cvss_vector": f.get("cvss_vector", ""),
            "confidence": f.get("confidence", ""),
            "cwe_id": f.get("cwe_id", ""),
            "injection_family": f.get("injection_family", ""),
            "injection_subtype": f.get("injection_subtype", ""),
            "affected_url": f.get("affected_url", ""),
            "affected_parameter": f.get("affected_parameter", ""),
            "payload": f.get("payload", ""),
            "description": f.get("description", ""),
            "verified": f.get("verified", False),
            "evidence": {
                "request": f.get("request_data", {}),
                "response": f.get("response_data", {}),
                "baseline_request": f.get("baseline_request", {}),
                "baseline_response": f.get("baseline_response", {}),
                "additional_evidence": f.get("evidence_json", {}),
            },
            "mitigation": f.get("mitigation", {}),
            "compliance": f.get("compliance", {}),
            "references": f.get("references", []),
        })

    report = {
        "report_metadata": {
            "title": report_context.get("title", ""),
            "generated_at": report_context.get("generated_at", ""),
            "scan_id": report_context.get("scan_id", ""),
            "format": "json",
            "generator": "InjectSentinel Reporting Engine",
        },
        "executive_summary": _serialize_value(report_context.get("executive_summary", {})),
        "scan_metadata": _serialize_value(report_context.get("scan_metadata", {})),
        "findings": json_findings,
        "compliance_mapping": _serialize_value(report_context.get("compliance", {})),
    }

    return json.dumps(report, indent=2, default=str).encode("utf-8")
