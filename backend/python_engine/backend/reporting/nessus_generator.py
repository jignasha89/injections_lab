"""
Nessus Generator - .nessus XML format compatible with Tenable import.

Generates a Nessus-format report using xml.etree.ElementTree that can be
imported into Tenable Nessus, Tenable.io, or other compatible scanners.
"""

import os
import logging
import uuid
import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import Dict, Any
from datetime import datetime

from backend.config import settings

logger = logging.getLogger(__name__)

NESSUS_SEVERITY_MAP = {
    "critical": "4",
    "high": "3",
    "medium": "2",
    "low": "1",
    "info": "0",
}

NESSUS_PLUGIN_FAMILY = "Web Application Testing"


def _cdata_element(parent: ET.Element, tag: str, text: str) -> ET.Element:
    """Create an element with CDATA content."""
    elem = ET.SubElement(parent, tag)
    elem.text = text
    return elem


async def generate_nessus(report_context: Dict[str, Any], output_path: str) -> str:
    """Generate a Nessus XML report.

    Args:
        report_context: Complete report data dictionary.
        output_path: Path to write the .nessus file.

    Returns:
        The output file path.
    """
    scan_meta = report_context.get("scan_metadata", {})
    findings = report_context.get("findings", [])

    # Build Nessus XML structure
    nessus = ET.Element("NessusClientData_v2")

    # Report element
    report = ET.SubElement(nessus, "Report")
    report_name = f"InjectSentinel Scan - {scan_meta.get('target_url', 'Unknown')}"
    report.set("name", report_name)

    # ReportHost element
    host = ET.SubElement(report, "ReportHost")
    target_url = scan_meta.get("target_url", "")
    # Extract hostname from URL
    hostname = target_url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    host.set("name", hostname)

    # HostProperties
    host_properties = ET.SubElement(host, "HostProperties")
    _cdata_element(host_properties, "tag", target_url).set("name", "host")
    _cdata_element(host_properties, "tag", scan_meta.get("scan_id", "")).set("name", "scan_id")
    _cdata_element(host_properties, "tag", scan_meta.get("start_time", "")).set("name", "scan_start")
    _cdata_element(host_properties, "tag", scan_meta.get("end_time", "")).set("name", "scan_end")
    _cdata_element(host_properties, "tag", "InjectSentinel").set("name", "scanner")
    _cdata_element(host_properties, "tag", str(len(findings))).set("name", "total_findings")

    # Generate unique plugin ID offset
    plugin_id_base = 90000

    for idx, finding in enumerate(findings):
        severity = (finding.get("severity", "info") or "info").lower()
        nessus_severity = NESSUS_SEVERITY_MAP.get(severity, "0")

        item = ET.SubElement(host, "ReportItem")
        plugin_id = plugin_id_base + idx
        item.set("pluginID", str(plugin_id))
        item.set("pluginName", finding.get("title", "Unknown Finding"))
        item.set("pluginFamily", NESSUS_PLUGIN_FAMILY)
        item.set("severity", nessus_severity)
        item.set("port", "443")
        item.set("svc_name", "https")
        item.set("protocol", "tcp")

        # Plugin output
        plugin_output = (
            f"Title: {finding.get('title', '')}\n"
            f"Severity: {finding.get('severity', '')}\n"
            f"CVSS Score: {finding.get('cvss_score', '')}\n"
            f"CVSS Vector: {finding.get('cvss_vector', '')}\n"
            f"CWE: {finding.get('cwe_id', '')}\n"
            f"Confidence: {finding.get('confidence', '')}\n"
            f"Affected URL: {finding.get('affected_url', '')}\n"
            f"Parameter: {finding.get('affected_parameter', '')}\n\n"
            f"Description:\n{finding.get('description', '')}\n\n"
            f"Payload:\n{finding.get('payload', '')}"
        )
        _cdata_element(item, "plugin_output", plugin_output)

        # Solution / remediation
        mitigation = finding.get("mitigation", {})
        solution = mitigation.get("remediation", "Apply input validation and output encoding.")
        _cdata_element(item, "solution", solution)

        # Risk information
        risk_info = ET.SubElement(item, "risk_information")
        cvss_base = ET.SubElement(risk_info, "cvss_base_score")
        cvss_base.text = str(finding.get("cvss_score", 0.0))
        cvss_temporal = ET.SubElement(risk_info, "cvss_temporal_score")
        cvss_temporal.text = str(finding.get("cvss_score", 0.0))
        cvss_vector = ET.SubElement(risk_info, "cvss_vector")
        cvss_vector.text = finding.get("cvss_vector", "")

        # Compliance data
        compliance = finding.get("compliance", {})
        owasp = compliance.get("owasp_top10", {})
        if owasp.get("category"):
            compliance_elem = ET.SubElement(item, "compliance")
            _cdata_element(compliance_elem, "check", f"OWASP Top 10 2021: {owasp.get('category')} - {owasp.get('title')}")

        pci = compliance.get("pci_dss_v4", {})
        if pci.get("requirement"):
            compliance_elem = ET.SubElement(item, "compliance")
            _cdata_element(compliance_elem, "check", f"PCI-DSS v4.0 Req {pci.get('requirement')} - {pci.get('title')}")

        # References
        refs = finding.get("references", []) or mitigation.get("references", [])
        if refs:
            refs_elem = ET.SubElement(item, "references")
            for ref in refs:
                ref_elem = ET.SubElement(refs_elem, "reference")
                ref_elem.set("source", "InjectSentinel")
                ref_elem.set("url", str(ref))

        # Evidence - request
        req_data = finding.get("request_data", {})
        if req_data:
            evidence = ET.SubElement(item, "evidence")
            req_elem = ET.SubElement(evidence, "request")
            req_elem.set("method", req_data.get("method", "GET"))
            req_elem.set("url", req_data.get("url", ""))
            if req_data.get("headers"):
                headers_elem = ET.SubElement(req_elem, "headers")
                for k, v in req_data["headers"].items():
                    h = ET.SubElement(headers_elem, "header")
                    h.set("name", k)
                    h.set("value", str(v))
            if req_data.get("body"):
                _cdata_element(req_elem, "body", req_data["body"])

        # Evidence - response
        resp_data = finding.get("response_data", {})
        if resp_data:
            evidence = item.find("evidence")
            if evidence is None:
                evidence = ET.SubElement(item, "evidence")
            resp_elem = ET.SubElement(evidence, "response")
            resp_elem.set("status", str(resp_data.get("status_code", "")))
            if resp_data.get("body"):
                _cdata_element(resp_elem, "body", resp_data["body"][:5000])

        # CVE / vulnerability ID
        vid = finding.get("vulnerability_id", "")
        if vid:
            cve_elem = ET.SubElement(item, "cve")
            cve_elem.text = vid

        # CWE
        cwe = finding.get("cwe_id", "")
        if cwe:
            cwe_elem = ET.SubElement(item, "cwe")
            cwe_elem.text = cwe

        # Synthesis
        synthesis = ET.SubElement(item, "synopsis")
        synthesis.text = f"InjectSentinel detected a {severity} severity injection vulnerability: {finding.get('title', '')}"

        # Description
        description = ET.SubElement(item, "description")
        description.text = finding.get("description", "")

        # See also
        see_also = ET.SubElement(item, "see_also")
        see_also.text = "https://owasp.org/www-community/attacks/"

    # Pretty print the XML
    rough_string = ET.tostring(nessus, encoding="unicode")
    parsed = minidom.parseString(rough_string)
    pretty_xml = parsed.toprettyxml(indent="  ", encoding=None)

    # Remove the XML declaration that minidom adds
    lines = pretty_xml.split("\n")
    if lines[0].startswith("<?xml"):
        lines = lines[1:]
    xml_output = '<?xml version="1.0" encoding="UTF-8"?>\n' + "\n".join(lines)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(xml_output)

    logger.info("Nessus report written to %s (%d findings)", output_path, len(findings))
    return output_path
