"""
PDF Generator - Professional PDF report generation using Jinja2 + WeasyPrint.

Generates a complete PDF with cover page, table of contents, color-coded severity,
request/response evidence blocks, CVSS badges, CWE references, and mitigation code blocks.
Supports company branding via logo and color overrides.
"""

import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime

import jinja2

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False
    HTML = None

from backend.config import settings

logger = logging.getLogger(__name__)

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

DEFAULT_BRAND = {
    "logo_path": "",
    "primary_color": "#1a1a2e",
    "secondary_color": "#16213e",
    "accent_color": "#0f3460",
    "danger_color": "#e74c3c",
    "warning_color": "#f39c12",
    "success_color": "#27ae60",
    "info_color": "#3498db",
    "company_name": "InjectSentinel",
    "report_subtitle": "Automated Injection Vulnerability Assessment",
}

SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#95a5a6",
}


def _create_jinja_env() -> jinja2.Environment:
    """Create Jinja2 environment with template loader."""
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
        autoescape=jinja2.select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _build_brand_css(brand: Dict[str, str]) -> str:
    """Generate CSS overrides from brand configuration."""
    return f"""
    :root {{
        --primary: {brand.get('primary_color', DEFAULT_BRAND['primary_color'])};
        --secondary: {brand.get('secondary_color', DEFAULT_BRAND['secondary_color'])};
        --accent: {brand.get('accent_color', DEFAULT_BRAND['accent_color'])};
        --danger: {brand.get('danger_color', DEFAULT_BRAND['danger_color'])};
        --warning: {brand.get('warning_color', DEFAULT_BRAND['warning_color'])};
        --success: {brand.get('success_color', DEFAULT_BRAND['success_color'])};
        --info: {brand.get('info_color', DEFAULT_BRAND['info_color'])};
    }}
    """


def _format_cvss_badge(score: float) -> str:
    """Generate HTML for a CVSS score badge."""
    if score >= 9.0:
        color = "#e74c3c"
        label = "Critical"
    elif score >= 7.0:
        color = "#e67e22"
        label = "High"
    elif score >= 4.0:
        color = "#f1c40f"
        label = "Medium"
    elif score >= 0.1:
        color = "#3498db"
        label = "Low"
    else:
        color = "#95a5a6"
        label = "None"
    return (
        f'<span class="cvss-badge" style="background-color:{color};color:#fff;'
        f'padding:2px 8px;border-radius:4px;font-weight:bold;">'
        f'{score:.1f} ({label})</span>'
    )


def _format_severity_class(severity: str) -> str:
    """Return CSS class name for a severity level."""
    return f"severity-{severity.lower()}"


def _format_request_block(request_data: Dict[str, Any]) -> str:
    """Format request data as an HTML evidence block."""
    if not request_data:
        return "<p class='no-evidence'>No request data available.</p>"
    parts = []
    if request_data.get("method"):
        parts.append(f"<strong>Method:</strong> {request_data['method']}")
    if request_data.get("url"):
        parts.append(f"<strong>URL:</strong> <code>{request_data['url']}</code>")
    if request_data.get("headers"):
        parts.append("<strong>Headers:</strong>")
        for k, v in request_data["headers"].items():
            parts.append(f"&nbsp;&nbsp;<code>{k}: {v}</code>")
    if request_data.get("body"):
        parts.append(f"<strong>Body:</strong>\n<pre>{request_data['body']}</pre>")
    return "<br>".join(parts)


def _format_response_block(response_data: Dict[str, Any]) -> str:
    """Format response data as an HTML evidence block."""
    if not response_data:
        return "<p class='no-evidence'>No response data available.</p>"
    parts = []
    if response_data.get("status_code"):
        parts.append(f"<strong>Status:</strong> {response_data['status_code']}")
    if response_data.get("headers"):
        parts.append("<strong>Headers:</strong>")
        for k, v in response_data["headers"].items():
            parts.append(f"&nbsp;&nbsp;<code>{k}: {v}</code>")
    if response_data.get("body"):
        truncated = response_data["body"][:5000]
        parts.append(f"<strong>Body (truncated):</strong>\n<pre>{truncated}</pre>")
    return "<br>".join(parts)


async def generate_pdf(
    report_context: Dict[str, Any],
    output_path: str,
    brand_config: Optional[Dict[str, str]] = None,
) -> str:
    """Generate a PDF report from the report context.

    Args:
        report_context: Complete report data dictionary.
        output_path: Path to write the PDF file.
        brand_config: Optional branding overrides.

    Returns:
        The output file path.
    """
    brand = {**DEFAULT_BRAND, **(brand_config or {})}

    env = _create_jinja_env()
    env.globals.update({
        "format_cvss_badge": _format_cvss_badge,
        "format_severity_class": _format_severity_class,
        "format_request_block": _format_request_block,
        "format_response_block": _format_response_block,
        "severity_colors": SEVERITY_COLORS,
        "brand": brand,
        "now": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    })

    base_template = env.get_template("report_base.html.j2")
    html_content = base_template.render(**report_context)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    HTML(string=html_content).write_pdf(output_path)
    logger.info("PDF report written to %s", output_path)
    return output_path
