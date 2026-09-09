"""
HTML Generator - Interactive self-contained HTML report.

Generates a single HTML file with embedded CSS, severity filtering,
expandable findings, and print-friendly layout.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from backend.config import settings

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#95a5a6",
}


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _format_request_block(req: Dict[str, Any]) -> str:
    """Format request data as HTML."""
    if not req:
        return '<div class="evidence-block"><p>No request data.</p></div>'
    parts = ['<div class="evidence-block request-block">']
    if req.get("method"):
        parts.append(f'<div class="method">{_escape_html(req["method"])}</div>')
    if req.get("url"):
        parts.append(f'<div class="url"><code>{_escape_html(req["url"])}</code></div>')
    if req.get("headers"):
        parts.append('<div class="headers"><strong>Headers:</strong><pre>')
        for k, v in req["headers"].items():
            parts.append(f'{_escape_html(k)}: {_escape_html(str(v))}')
        parts.append("</pre></div>")
    if req.get("body"):
        parts.append(f'<div class="body"><strong>Body:</strong><pre>{_escape_html(req["body"][:3000])}</pre></div>')
    parts.append("</div>")
    return "\n".join(parts)


def _format_response_block(resp: Dict[str, Any]) -> str:
    """Format response data as HTML."""
    if not resp:
        return '<div class="evidence-block"><p>No response data.</p></div>'
    parts = ['<div class="evidence-block response-block">']
    if resp.get("status_code"):
        parts.append(f'<div class="status">Status: {resp["status_code"]}</div>')
    if resp.get("headers"):
        parts.append('<div class="headers"><strong>Headers:</strong><pre>')
        for k, v in resp["headers"].items():
            parts.append(f'{_escape_html(k)}: {_escape_html(str(v))}')
        parts.append("</pre></div>")
    if resp.get("body"):
        parts.append(f'<div class="body"><strong>Body:</strong><pre>{_escape_html(resp["body"][:3000])}</pre></div>')
    parts.append("</div>")
    return "\n".join(parts)


def _render_finding_html(finding: Dict[str, Any], index: int) -> str:
    """Render a single finding as HTML."""
    severity = finding.get("severity", "info").lower()
    color = SEVERITY_COLORS.get(severity, "#95a5a6")
    verified_badge = '<span class="badge verified">Verified</span>' if finding.get("verified") else '<span class="badge unverified">Unverified</span>'

    code_examples = finding.get("mitigation", {}).get("code_examples", {})
    code_blocks_html = ""
    for lang, examples in code_examples.items():
        if examples.get("vulnerable") or examples.get("fixed"):
            code_blocks_html += f'<div class="code-example"><h5>{_escape_html(lang.upper())}</h5>'
            if examples.get("vulnerable"):
                code_blocks_html += f'<div class="code-vulnerable"><h6>Vulnerable:</h6><pre><code>{_escape_html(examples["vulnerable"])}</code></pre></div>'
            if examples.get("fixed"):
                code_blocks_html += f'<div class="code-fixed"><h6>Fixed:</h6><pre><code>{_escape_html(examples["fixed"])}</code></pre></div>'
            code_blocks_html += "</div>"

    waf_rules = finding.get("mitigation", {}).get("waf_rules", {}).get("modsecurity", [])
    waf_html = ""
    if waf_rules:
        waf_html = '<div class="waf-rules"><h5>ModSecurity WAF Rules</h5><pre>'
        for rule in waf_rules:
            waf_html += f'<code>{_escape_html(rule)}</code>\n'
        waf_html += "</pre></div>"

    refs = finding.get("references", []) or finding.get("mitigation", {}).get("references", [])
    refs_html = ""
    if refs:
        refs_html = '<div class="references"><h5>References</h5><ul>'
        for ref in refs:
            refs_html += f'<li><a href="{_escape_html(str(ref))}" target="_blank">{_escape_html(str(ref))}</a></li>'
        refs_html += "</ul></div>"

    compliance = finding.get("compliance", {})
    owasp = compliance.get("owasp_top10", {})
    pci = compliance.get("pci_dss_v4", {})
    cwes = compliance.get("cwe", [])
    compliance_html = '<div class="compliance-mapping"><h5>Compliance Mapping</h5><table>'
    if owasp.get("category") != "N/A":
        compliance_html += f'<tr><td>OWASP Top 10</td><td>{_escape_html(owasp.get("category", ""))} - {_escape_html(owasp.get("title", ""))}</td></tr>'
    if pci.get("requirement") != "N/A":
        compliance_html += f'<tr><td>PCI-DSS v4.0</td><td>Req {_escape_html(pci.get("requirement", ""))} - {_escape_html(pci.get("title", ""))}</td></tr>'
    for cwe in cwes:
        compliance_html += f'<tr><td>CWE</td><td>{_escape_html(cwe.get("cwe", ""))} - {_escape_html(cwe.get("name", ""))}</td></tr>'
    compliance_html += "</table></div>"

    return f"""
    <div class="finding-card" data-severity="{severity}" id="finding-{index}">
      <div class="finding-header" onclick="toggleFinding({index})">
        <div class="finding-title">
          <span class="severity-dot" style="background:{color};"></span>
          <h3>{_escape_html(finding.get("title", "Unknown"))}</h3>
          {verified_badge}
        </div>
        <div class="finding-meta">
          <span class="cvss" style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;">CVSS: {finding.get("cvss_score", "N/A")}</span>
          <span class="severity-label" style="color:{color};font-weight:bold;">{finding.get("severity", "N/A").upper()}</span>
          <span class="cwe">{_escape_html(finding.get("cwe_id", ""))}</span>
          <span class="expand-icon" id="expand-{index}">▼</span>
        </div>
      </div>
      <div class="finding-body" id="body-{index}" style="display:none;">
        <div class="detail-section">
          <h4>Description</h4>
          <p>{_escape_html(finding.get("description", "No description available."))}</p>
        </div>
        <div class="detail-section">
          <h4>Affected Endpoint</h4>
          <p><strong>URL:</strong> <code>{_escape_html(finding.get("affected_url", ""))}</code></p>
          <p><strong>Parameter:</strong> <code>{_escape_html(finding.get("affected_parameter", ""))}</code></p>
        </div>
        <div class="detail-section">
          <h4>Payload</h4>
          <pre><code>{_escape_html(finding.get("payload", ""))}</code></pre>
        </div>
        <div class="detail-section">
          <h4>Request Evidence</h4>
          {_format_request_block(finding.get("request_data", {}))}
        </div>
        <div class="detail-section">
          <h4>Response Evidence</h4>
          {_format_response_block(finding.get("response_data", {}))}
        </div>
        <div class="detail-section">
          <h4>CVSS Vector</h4>
          <code>{_escape_html(finding.get("cvss_vector", "N/A"))}</code>
        </div>
        {compliance_html}
        <div class="detail-section">
          <h4>Remediation</h4>
          <p>{_escape_html(finding.get("mitigation", {}).get("remediation", "Refer to general injection prevention guidelines."))}</p>
        </div>
        {code_blocks_html}
        {waf_html}
        {refs_html}
      </div>
    </div>
    """


async def generate_html(report_context: Dict[str, Any], output_path: str) -> str:
    """Generate a self-contained HTML report.

    Args:
        report_context: Complete report data dictionary.
        output_path: Path to write the HTML file.

    Returns:
        The output file path.
    """
    exec_summary = report_context.get("executive_summary", {})
    scan_meta = report_context.get("scan_metadata", {})
    findings = report_context.get("findings", [])
    compliance = report_context.get("compliance", {})
    mitigation_items = report_context.get("mitigation_items", [])

    severity_counts = exec_summary.get("severity_counts", {})

    findings_html = ""
    for i, finding in enumerate(findings):
        findings_html += _render_finding_html(finding, i)

    compliance_rows = ""
    for mapping in compliance.get("mappings", []):
        cwe_str = ", ".join(mapping.get("cwe_ids", []))
        compliance_rows += f"""
        <tr>
          <td>{_escape_html(mapping.get("family", ""))}</td>
          <td>{_escape_html(mapping.get("owasp_category", ""))}</td>
          <td>{_escape_html(mapping.get("pci_requirement", ""))}</td>
          <td>{_escape_html(cwe_str)}</td>
        </tr>
        """

    mitigation_html = ""
    for item in mitigation_items:
        mitigation_html += f"""
        <div class="mitigation-card">
          <h4>{_escape_html(item.get("title", ""))}</h4>
          <p><strong>Injection Sub-type:</strong> {_escape_html(item.get("injection_subtype", ""))}</p>
          <p>{_escape_html(item.get("description", ""))}</p>
          <p><strong>Remediation:</strong> {_escape_html(item.get("remediation", ""))}</p>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_escape_html(report_context.get("title", "Vulnerability Report"))}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f6fa; color: #2c3e50; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
.header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 40px; border-radius: 8px; margin-bottom: 30px; }}
.header h1 {{ font-size: 28px; margin-bottom: 10px; }}
.header p {{ opacity: 0.8; }}
.section {{ background: white; border-radius: 8px; padding: 30px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }}
.section h2 {{ color: #1a1a2e; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #eee; }}
.severity-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 20px; }}
.severity-card {{ padding: 20px; border-radius: 8px; text-align: center; color: white; font-weight: bold; }}
.severity-card .count {{ font-size: 32px; display: block; }}
.severity-card .label {{ font-size: 12px; text-transform: uppercase; opacity: 0.9; }}
.filter-bar {{ margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
.filter-btn {{ padding: 8px 16px; border: 2px solid #ddd; border-radius: 20px; background: white; cursor: pointer; font-size: 13px; transition: all 0.2s; }}
.filter-btn:hover {{ border-color: #1a1a2e; }}
.filter-btn.active {{ background: #1a1a2e; color: white; border-color: #1a1a2e; }}
.finding-card {{ border: 1px solid #eee; border-radius: 8px; margin-bottom: 15px; overflow: hidden; }}
.finding-header {{ padding: 15px 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; transition: background 0.2s; }}
.finding-header:hover {{ background: #f8f9fa; }}
.finding-title {{ display: flex; align-items: center; gap: 12px; }}
.severity-dot {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}
.finding-title h3 {{ font-size: 16px; margin: 0; }}
.finding-meta {{ display: flex; align-items: center; gap: 10px; font-size: 13px; }}
.badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
.badge.verified {{ background: #27ae60; color: white; }}
.badge.unverified {{ background: #95a5a6; color: white; }}
.finding-body {{ padding: 20px; border-top: 1px solid #eee; background: #fafbfc; }}
.detail-section {{ margin-bottom: 20px; }}
.detail-section h4 {{ color: #1a1a2e; margin-bottom: 8px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; }}
.detail-section p {{ margin-bottom: 8px; }}
.evidence-block {{ background: white; border: 1px solid #e0e0e0; border-radius: 4px; padding: 12px; margin-top: 8px; }}
.evidence-block pre {{ background: #2d2d2d; color: #f8f8f2; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; margin-top: 8px; }}
.evidence-block code {{ font-family: 'Consolas', 'Monaco', monospace; }}
pre code {{ font-family: 'Consolas', 'Monaco', monospace; }}
.compliance-mapping table {{ width: 100%; border-collapse: collapse; }}
.compliance-mapping td {{ padding: 8px 12px; border-bottom: 1px solid #eee; font-size: 13px; }}
.compliance-mapping td:first-child {{ font-weight: bold; width: 200px; }}
.mitigation-card {{ border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; margin-bottom: 15px; }}
.mitigation-card h4 {{ color: #1a1a2e; margin-bottom: 8px; }}
.code-example {{ margin-top: 10px; }}
.code-example h5 {{ font-size: 13px; margin-bottom: 6px; color: #555; }}
.code-vulnerable pre {{ background: #fff5f5; border: 1px solid #e74c3c; }}
.code-fixed pre {{ background: #f0fff4; border: 1px solid #27ae60; }}
.waf-rules pre {{ background: #2d2d2d; color: #f8f8f2; padding: 12px; border-radius: 4px; font-size: 11px; overflow-x: auto; }}
.references ul {{ list-style: none; padding: 0; }}
.references li {{ margin-bottom: 4px; }}
.references a {{ color: #3498db; text-decoration: none; font-size: 13px; }}
.references a:hover {{ text-decoration: underline; }}
.expand-icon {{ transition: transform 0.2s; font-size: 12px; }}
.expand-icon.rotated {{ transform: rotate(180deg); }}
.meta-info {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
.meta-info dt {{ font-weight: bold; color: #555; }}
.meta-info dd {{ margin-bottom: 10px; }}
.footer {{ text-align: center; padding: 20px; color: #95a5a6; font-size: 12px; }}
@media print {{
  .filter-bar {{ display: none; }}
  .finding-body {{ display: block !important; }}
  .section {{ break-inside: avoid; }}
}}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>{_escape_html(report_context.get("title", "Vulnerability Report"))}</h1>
  <p>Generated: {_escape_html(report_context.get("generated_at", ""))}</p>
  <p>Scan ID: {_escape_html(report_context.get("scan_id", ""))}</p>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="severity-grid">
    <div class="severity-card" style="background:#e74c3c;"><span class="count">{severity_counts.get("critical", 0)}</span><span class="label">Critical</span></div>
    <div class="severity-card" style="background:#e67e22;"><span class="count">{severity_counts.get("high", 0)}</span><span class="label">High</span></div>
    <div class="severity-card" style="background:#f1c40f;color:#333;"><span class="count">{severity_counts.get("medium", 0)}</span><span class="label">Medium</span></div>
    <div class="severity-card" style="background:#3498db;"><span class="count">{severity_counts.get("low", 0)}</span><span class="label">Low</span></div>
    <div class="severity-card" style="background:#95a5a6;"><span class="count">{severity_counts.get("info", 0)}</span><span class="label">Info</span></div>
  </div>
  <p><strong>Overall Risk Level:</strong> {_escape_html(exec_summary.get("risk_level", "N/A"))}</p>
  <p><strong>Total Findings:</strong> {exec_summary.get("total_findings", 0)}</p>
  <p><strong>Target:</strong> {_escape_html(exec_summary.get("target_url", ""))}</p>
</div>

<div class="section">
  <h2>Scan Metadata</h2>
  <dl class="meta-info">
    <dt>Scan ID</dt><dd>{_escape_html(scan_meta.get("scan_id", ""))}</dd>
    <dt>Target URL</dt><dd>{_escape_html(scan_meta.get("target_url", ""))}</dd>
    <dt>Start Time</dt><dd>{_escape_html(scan_meta.get("start_time", ""))}</dd>
    <dt>End Time</dt><dd>{_escape_html(scan_meta.get("end_time", ""))}</dd>
    <dt>Status</dt><dd>{_escape_html(scan_meta.get("status", ""))}</dd>
    <dt>Tools Used</dt><dd>{_escape_html(", ".join(scan_meta.get("tools_used", [])))}</dd>
  </dl>
</div>

<div class="section">
  <h2>Vulnerability Findings ({len(findings)})</h2>
  <div class="filter-bar">
    <span style="font-weight:bold;margin-right:5px;">Filter:</span>
    <button class="filter-btn active" onclick="filterFindings('all')">All</button>
    <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
    <button class="filter-btn" onclick="filterFindings('high')">High</button>
    <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
    <button class="filter-btn" onclick="filterFindings('low')">Low</button>
    <button class="filter-btn" onclick="filterFindings('info')">Info</button>
  </div>
  <div id="findings-container">
    {findings_html}
  </div>
</div>

<div class="section">
  <h2>Mitigation Reference</h2>
  {mitigation_html if mitigation_html else "<p>No mitigation data available.</p>"}
</div>

<div class="section">
  <h2>Compliance Mapping</h2>
  <table style="width:100%;border-collapse:collapse;">
    <thead>
      <tr style="background:#f8f9fa;"><th style="padding:10px;text-align:left;border-bottom:2px solid #eee;">Family</th><th style="padding:10px;text-align:left;border-bottom:2px solid #eee;">OWASP 2021</th><th style="padding:10px;text-align:left;border-bottom:2px solid #eee;">PCI-DSS v4.0</th><th style="padding:10px;text-align:left;border-bottom:2px solid #eee;">CWE</th></tr>
    </thead>
    <tbody>
      {compliance_rows}
    </tbody>
  </table>
</div>

<div class="footer">
  <p>Generated by InjectSentinel | {_escape_html(report_context.get("generated_at", ""))}</p>
</div>

</div>

<script>
function toggleFinding(index) {{
  var body = document.getElementById('body-' + index);
  var icon = document.getElementById('expand-' + index);
  if (body.style.display === 'none') {{
    body.style.display = 'block';
    icon.classList.add('rotated');
  }} else {{
    body.style.display = 'none';
    icon.classList.remove('rotated');
  }}
}}

function filterFindings(severity) {{
  var cards = document.querySelectorAll('.finding-card');
  var btns = document.querySelectorAll('.filter-btn');
  btns.forEach(function(btn) {{ btn.classList.remove('active'); }});
  event.target.classList.add('active');
  cards.forEach(function(card) {{
    if (severity === 'all' || card.getAttribute('data-severity') === severity) {{
      card.style.display = 'block';
    }} else {{
      card.style.display = 'none';
    }}
  }});
}}
</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info("HTML report written to %s (%d findings)", output_path, len(findings))
    return output_path
