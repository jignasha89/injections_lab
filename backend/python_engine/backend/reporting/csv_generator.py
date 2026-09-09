"""
CSV Generator - Flat CSV export of vulnerability findings.

Exports a UTF-8 with BOM CSV file for easy import into Excel and other tools.
Columns: ID, Title, Severity, CVSS, Confidence, URL, Parameter, Family,
Subtype, CWE, Verified, Description.
"""

import csv
import os
import logging
from typing import Dict, Any, List
from io import StringIO

from backend.config import settings

logger = logging.getLogger(__name__)

CSV_COLUMNS = [
    "ID",
    "Title",
    "Severity",
    "CVSS Score",
    "CVSS Vector",
    "Confidence",
    "Affected URL",
    "Affected Parameter",
    "Injection Family",
    "Injection Subtype",
    "CWE ID",
    "Vulnerability ID",
    "Verified",
    "Description",
    "Payload",
    "References",
]


def _finding_to_row(finding: Dict[str, Any]) -> Dict[str, str]:
    """Convert a finding dict to a flat CSV row."""
    refs = finding.get("references", [])
    if isinstance(refs, list):
        refs_str = "; ".join(str(r) for r in refs)
    else:
        refs_str = str(refs)

    return {
        "ID": finding.get("id", ""),
        "Title": finding.get("title", ""),
        "Severity": finding.get("severity", ""),
        "CVSS Score": str(finding.get("cvss_score", "")),
        "CVSS Vector": finding.get("cvss_vector", ""),
        "Confidence": finding.get("confidence", ""),
        "Affected URL": finding.get("affected_url", ""),
        "Affected Parameter": finding.get("affected_parameter", ""),
        "Injection Family": finding.get("injection_family", ""),
        "Injection Subtype": finding.get("injection_subtype", ""),
        "CWE ID": finding.get("cwe_id", ""),
        "Vulnerability ID": finding.get("vulnerability_id", ""),
        "Verified": "Yes" if finding.get("verified") else "No",
        "Description": finding.get("description", ""),
        "Payload": finding.get("payload", ""),
        "References": refs_str,
    }


async def generate_csv(report_context: Dict[str, Any], output_path: str) -> str:
    """Generate a CSV report from the report context.

    Args:
        report_context: Complete report data dictionary.
        output_path: Path to write the CSV file.

    Returns:
        The output file path.
    """
    findings = report_context.get("findings", [])

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for finding in findings:
            row = _finding_to_row(finding)
            writer.writerow(row)

    logger.info("CSV report written to %s (%d findings)", output_path, len(findings))
    return output_path


async def generate_csv_bytes(report_context: Dict[str, Any]) -> bytes:
    """Generate a CSV report and return as bytes (for API responses).

    Args:
        report_context: Complete report data dictionary.

    Returns:
        CSV content as bytes with UTF-8 BOM.
    """
    findings = report_context.get("findings", [])
    output = StringIO()
    output.write("\ufeff")  # UTF-8 BOM

    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for finding in findings:
        row = _finding_to_row(finding)
        writer.writerow(row)

    return output.getvalue().encode("utf-8")
