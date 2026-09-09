"""
Compliance Mapper - Maps injection families to regulatory standards and CWE IDs.

Covers all 14 injection families with mappings to:
- OWASP Top 10 2021
- PCI-DSS v4.0 Requirement 6.5
- CWE/SANS Top 25
"""

from typing import Dict, List, Any

# ── Injection Family → OWASP Top 10 2021 ──────────────────────────────────────

OWASP_TOP10_2021: Dict[str, Dict[str, str]] = {
    "SQL Injection": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "User-supplied data is not validated, filtered, or sanitized by the application.",
        "risk": "Critical",
    },
    "NoSQL Injection": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "NoSQL databases receive unsanitized input leading to data exfiltration.",
        "risk": "Critical",
    },
    "OS Command Injection": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "Untrusted data is sent to an interpreter as part of a command.",
        "risk": "Critical",
    },
    "LDAP Injection": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "User-supplied LDAP statements are not properly sanitized.",
        "risk": "High",
    },
    "XPath Injection": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "XPath queries use unsanitized user input, allowing query manipulation.",
        "risk": "High",
    },
    "XML External Entity (XXE)": {
        "category": "A05:2021",
        "title": "Security Misconfiguration",
        "description": "XML parsers process external entities from untrusted input.",
        "risk": "High",
    },
    "HTML Injection": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "User input is embedded in HTML output without encoding.",
        "risk": "Medium",
    },
    "Cross-Site Scripting (XSS)": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "Client-side scripts execute with attacker-controlled data.",
        "risk": "High",
    },
    "Server-Side Template Injection (SSTI)": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "Template engines process unsanitized user input as template directives.",
        "risk": "Critical",
    },
    "CRLF Injection": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "Carriage-return/line-feed characters injected into HTTP headers.",
        "risk": "Medium",
    },
    "Header Injection": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "User input injected into HTTP response headers.",
        "risk": "Medium",
    },
    "Log Injection": {
        "category": "A09:2021",
        "title": "Security Logging and Monitoring Failures",
        "description": "User input injected into log entries causes log forging or injection.",
        "risk": "Medium",
    },
    "Expression Language Injection": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "EL expressions evaluated from user input lead to remote code execution.",
        "risk": "High",
    },
    "Carriage Return / Line Feed Injection": {
        "category": "A03:2021",
        "title": "Injection",
        "description": "CR/LF characters injected into protocol-level data.",
        "risk": "Medium",
    },
}

# ── Injection Family → PCI-DSS v4.0 Requirement 6.5.x ────────────────────────

PCI_DSS_V4: Dict[str, Dict[str, str]] = {
    "SQL Injection": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – SQL Injection",
        "description": "Applications must protect against injection attacks including SQL injection.",
        "severity": "Critical",
    },
    "NoSQL Injection": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – NoSQL Injection",
        "description": "Non-relational database queries must be parameterized and sanitized.",
        "severity": "Critical",
    },
    "OS Command Injection": {
        "requirement": "6.5.2",
        "title": "Injection Flaws – OS Command Injection",
        "description": "Operating system commands must not incorporate untrusted input.",
        "severity": "Critical",
    },
    "LDAP Injection": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – LDAP Injection",
        "description": "LDAP queries must use parameterized approaches.",
        "severity": "High",
    },
    "XPath Injection": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – XPath Injection",
        "description": "XPath queries must use parameterized approaches.",
        "severity": "High",
    },
    "XML External Entity (XXE)": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – XML External Entity",
        "description": "XML parsers must disable external entity processing.",
        "severity": "High",
    },
    "HTML Injection": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – HTML Injection",
        "description": "Output encoding must prevent HTML injection in responses.",
        "severity": "Medium",
    },
    "Cross-Site Scripting (XSS)": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – Cross-Site Scripting",
        "description": "Input validation and output encoding must prevent XSS.",
        "severity": "High",
    },
    "Server-Side Template Injection (SSTI)": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – SSTI",
        "description": "Template engines must not evaluate user-controlled input as code.",
        "severity": "Critical",
    },
    "CRLF Injection": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – CRLF Injection",
        "description": "CR/LF characters must be filtered from user input used in headers.",
        "severity": "Medium",
    },
    "Header Injection": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – Header Injection",
        "description": "HTTP headers must not contain unvalidated user data.",
        "severity": "Medium",
    },
    "Log Injection": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – Log Injection",
        "description": "Log entries must sanitize user input to prevent log forging.",
        "severity": "Medium",
    },
    "Expression Language Injection": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – EL Injection",
        "description": "Expression language evaluation must be restricted from user input.",
        "severity": "High",
    },
    "Carriage Return / Line Feed Injection": {
        "requirement": "6.5.1",
        "title": "Injection Flaws – CRLF Injection",
        "description": "CR/LF sequences must be stripped from protocol-level input.",
        "severity": "Medium",
    },
}

# ── Injection Family → CWE IDs ─────────────────────────────────────────────────

CWE_MAPPING: Dict[str, List[Dict[str, str]]] = {
    "SQL Injection": [
        {"cwe": "CWE-89", "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"},
    ],
    "NoSQL Injection": [
        {"cwe": "CWE-943", "name": "Improper Neutralization of Special Elements in Data Query Logic"},
    ],
    "OS Command Injection": [
        {"cwe": "CWE-78", "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"},
    ],
    "LDAP Injection": [
        {"cwe": "CWE-90", "name": "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')"},
    ],
    "XPath Injection": [
        {"cwe": "CWE-91", "name": "XML Injection"},
    ],
    "XML External Entity (XXE)": [
        {"cwe": "CWE-611", "name": "Improper Restriction of XML External Entity Reference"},
        {"cwe": "CWE-776", "name": "Improper Restriction of Recursive Entity References in DTDs"},
    ],
    "HTML Injection": [
        {"cwe": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
    ],
    "Cross-Site Scripting (XSS)": [
        {"cwe": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
    ],
    "Server-Side Template Injection (SSTI)": [
        {"cwe": "CWE-1336", "name": "Improper Neutralization of Special Elements Used in a Template Engine"},
    ],
    "CRLF Injection": [
        {"cwe": "CWE-113", "name": "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')"},
    ],
    "Header Injection": [
        {"cwe": "CWE-113", "name": "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')"},
    ],
    "Log Injection": [
        {"cwe": "CWE-117", "name": "Improper Output Neutralization for Logs"},
    ],
    "Expression Language Injection": [
        {"cwe": "CWE-917", "name": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')"},
    ],
    "Carriage Return / Line Feed Injection": [
        {"cwe": "CWE-113", "name": "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')"},
    ],
}

# ── Helper Functions ────────────────────────────────────────────────────────────

def get_owasp_mapping(family: str) -> Dict[str, str]:
    """Return OWASP Top 10 2021 mapping for an injection family."""
    return OWASP_TOP10_2021.get(family, {
        "category": "N/A",
        "title": "Unknown Family",
        "description": "No OWASP mapping available for this family.",
        "risk": "Unknown",
    })


def get_pci_dss_mapping(family: str) -> Dict[str, str]:
    """Return PCI-DSS v4.0 Req 6.5 mapping for an injection family."""
    return PCI_DSS_V4.get(family, {
        "requirement": "N/A",
        "title": "Unknown Family",
        "description": "No PCI-DSS mapping available for this family.",
        "severity": "Unknown",
    })


def get_cwe_mapping(family: str) -> List[Dict[str, str]]:
    """Return CWE ID list for an injection family."""
    return CWE_MAPPING.get(family, [])


def get_all_mappings(family: str) -> Dict[str, Any]:
    """Return combined OWASP + PCI-DSS + CWE mappings for a family."""
    return {
        "owasp_top10": get_owasp_mapping(family),
        "pci_dss_v4": get_pci_dss_mapping(family),
        "cwe": get_cwe_mapping(family),
    }


def get_mapped_families() -> List[str]:
    """Return all injection families that have compliance mappings."""
    return list(OWASP_TOP10_2021.keys())


def build_compliance_table(families: List[str]) -> List[Dict[str, Any]]:
    """Build a full compliance mapping table for a list of families."""
    rows = []
    for family in families:
        owasp = get_owasp_mapping(family)
        pci = get_pci_dss_mapping(family)
        cwes = get_cwe_mapping(family)
        rows.append({
            "family": family,
            "owasp_category": owasp.get("category", "N/A"),
            "owasp_title": owasp.get("title", "N/A"),
            "owasp_risk": owasp.get("risk", "N/A"),
            "pci_requirement": pci.get("requirement", "N/A"),
            "pci_title": pci.get("title", "N/A"),
            "pci_severity": pci.get("severity", "N/A"),
            "cwe_ids": [c["cwe"] for c in cwes],
            "cwe_names": [c["name"] for c in cwes],
        })
    return rows


def build_compliance_summary(families: List[str]) -> Dict[str, Any]:
    """Build a compliance summary object for report sections."""
    table = build_compliance_table(families)
    return {
        "total_families": len(table),
        "owasp_categories": list({r["owasp_category"] for r in table if r["owasp_category"] != "N/A"}),
        "pci_requirements": list({r["pci_requirement"] for r in table if r["pci_requirement"] != "N/A"}),
        "unique_cwes": list({c for r in table for c in r["cwe_ids"]}),
        "mappings": table,
    }
