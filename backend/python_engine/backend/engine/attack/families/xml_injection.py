import logging
import httpx
import asyncio
import re
import time
import json
import uuid
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from backend.api.websocket import emit_finding, emit_tool_output

logger = logging.getLogger(__name__)

XXE_EXTERNAL_PATTERNS = [
    r"root:x:0:0",
    r"\[boot loader\]",
    r"daemon:",
    r"/bin/bash",
    r"/bin/sh",
    r"/etc/passwd",
    r"/etc/shadow",
    r"nt authority\\system",
    r"windows.*?system32",
    r"\[extensions\]",
    r"boot\.ini",
    r"win\.ini",
    r"php\.ini",
    r"/proc/self/environ",
    r"java\.io\.FileInputStream",
]

XXE_ERROR_PATTERNS = [
    r"XML parsing error",
    r"SAXParseException",
    r"lxml\.etree",
    r"xml\.parsers\.expat",
    r"DTD.*?not found",
    r"entity.*?not defined",
    r"External entity",
    r"ENTITY.*?SYSTEM",
    r"XMLSyntaxError",
    r"not well-formed",
    r"parser error",
    r"Elementary",
    r"SimpleXMLElement",
    r"DOMDocument",
    r"xmlstarlet",
]

XXE_OOB_PATTERNS = [
    r"xxe",
    r"external entity",
    r"parameter entity",
    r"SYSTEM.*?file:",
    r"SYSTEM.*?expect:",
    r"SYSTEM.*?php:",
    r"SYSTEM.*?gopher:",
    r"SYSTEM.*?dict:",
    r"SYSTEM.*?http:",
    r"SYSTEM.*?ftp:",
]

XSLT_PATTERNS = [
    r"XSLT",
    r"xslt\.process",
    r"XsltCompileException",
    r"StylesheetRoot",
    r"javax\.xml\.transform",
    r"net\.sf\.saxon",
    r"libxslt",
    r"XSLTProcessor",
    r"XsltSettings",
    r"xsl:stylesheet",
    r"xml-stylesheet",
    r"XPathEvaluator",
    r"exslt",
]

XSLT_EXPLOIT_INDICATORS = [
    r"uid=\d+",
    r"gid=\d+",
    r"root:",
    r"\[boot loader\]",
    r"Windows IP Configuration",
    r"phpinfo",
    r"PHP Version",
]


class XMLInjectionScanner:
    def __init__(self, timeout: int = 30, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._findings = []

    async def scan(self, element: dict, payloads: list[dict]) -> list[dict]:
        findings = []
        url = element.get("url", "")
        param_name = element.get("parameter_name", "")
        method = element.get("http_method", "GET").upper()
        scan_id = element.get("scan_id", "")

        if not url or not param_name:
            return findings

        try:
            baseline = await self._get_baseline(url, method, param_name)
        except Exception as e:
            logger.error(f"XML injection baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "xxe_external")
            payload_str = payload.get("payload_string", "")

            if subtype == "xxe_external":
                result = await self._test_xxe_external(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "xxe_parameter":
                result = await self._test_xxe_parameter(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "xxe_oob":
                result = await self._test_xxe_oob(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "xslt_injection":
                result = await self._test_xslt_injection(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_xxe_external(
                    url, method, param_name, payload_str, baseline
                )

            if result:
                findings.append(result)

        self._findings = findings
        return findings

    async def _get_baseline(self, url: str, method: str, param_name: str) -> dict:
        start = time.time()
        async with httpx.AsyncClient(
            verify=self.verify_ssl, timeout=self.timeout, follow_redirects=True
        ) as client:
            if method == "GET":
                resp = await client.get(url)
            else:
                resp = await client.post(url, data={param_name: "baseline"})
            elapsed = time.time() - start
            return {
                "status_code": resp.status_code,
                "body": resp.text,
                "body_length": len(resp.text),
                "response_time": elapsed,
                "headers": dict(resp.headers),
            }

    async def _send_payload(
        self, url: str, method: str, param_name: str, payload: str
    ) -> dict:
        start = time.time()
        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout, follow_redirects=True
            ) as client:
                headers = {"Content-Type": "application/xml"}
                if method == "GET":
                    inject_url = f"{url}?{param_name}={urlencode({'xml': payload})}"
                    resp = await client.get(inject_url, headers=headers)
                else:
                    resp = await client.post(url, content=payload, headers=headers)
                elapsed = time.time() - start
                return {
                    "status_code": resp.status_code,
                    "body": resp.text,
                    "body_length": len(resp.text),
                    "response_time": elapsed,
                    "headers": dict(resp.headers),
                    "error": None,
                }
        except httpx.TimeoutException:
            return {"status_code": 0, "body": "", "body_length": 0, "response_time": time.time() - start, "headers": {}, "error": "timeout"}
        except Exception as e:
            return {"status_code": 0, "body": "", "body_length": 0, "response_time": time.time() - start, "headers": {}, "error": str(e)}

    def _create_finding(
        self, title: str, description: str, severity: str, cvss: float,
        confidence: str, family: str, subtype: str, payload: str,
        request_data: dict, response_data: dict, evidence: dict
    ) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "title": title,
            "description": description,
            "severity": severity,
            "cvss_score": cvss,
            "confidence": confidence,
            "injection_family": family,
            "injection_subtype": subtype,
            "payload": payload,
            "request_data": request_data,
            "response_data": response_data,
            "evidence_json": json.dumps(evidence),
        }

    def _match_patterns(self, body: str, patterns: list[str]) -> list[str]:
        matches = []
        body_lower = body.lower()
        for pattern in patterns:
            if re.search(pattern, body_lower, re.IGNORECASE):
                matches.append(pattern)
        return matches

    async def _test_xxe_external(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        external_matches = self._match_patterns(body, XXE_EXTERNAL_PATTERNS)
        error_matches = self._match_patterns(body, XXE_ERROR_PATTERNS)

        if external_matches:
            return self._create_finding(
                title="XML Injection - XXE External Entity",
                description=f"XXE external entity injection detected. File content leaked: {', '.join(external_matches[:3])}",
                severity="critical",
                cvss=9.8,
                confidence="high",
                family="xml_injection",
                subtype="xxe_external",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"external_patterns": external_matches[:5], "file_content_leaked": True},
            )

        if error_matches:
            return self._create_finding(
                title="XML Injection - XXE (Error Disclosure)",
                description=f"XXE injection attempt detected via error disclosure: {', '.join(error_matches[:3])}",
                severity="high",
                cvss=8.1,
                confidence="medium",
                family="xml_injection",
                subtype="xxe_external",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"error_patterns": error_matches[:5]},
            )

        if resp["status_code"] != baseline["status_code"] and ("<!" in payload or "ENTITY" in payload):
            return self._create_finding(
                title="XML Injection - XXE (Status Anomaly)",
                description="XXE payload caused status code anomaly.",
                severity="medium",
                cvss=6.5,
                confidence="low",
                family="xml_injection",
                subtype="xxe_external",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"status_change": True},
            )
        return None

    async def _test_xxe_parameter(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        all_matches = self._match_patterns(body, XXE_EXTERNAL_PATTERNS + XXE_ERROR_PATTERNS)

        if all_matches:
            return self._create_finding(
                title="XML Injection - XXE Parameter Entity",
                description=f"XXE parameter entity injection detected: {', '.join(all_matches[:3])}",
                severity="critical",
                cvss=9.8,
                confidence="medium",
                family="xml_injection",
                subtype="xxe_parameter",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"matched_patterns": all_matches[:5]},
            )
        return None

    async def _test_xxe_oob(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        oob_matches = self._match_patterns(body, XXE_OOB_PATTERNS)

        if oob_matches:
            return self._create_finding(
                title="XML Injection - XXE Out-of-Band",
                description=f"XXE out-of-band injection detected. Protocol handlers: {', '.join(oob_matches[:3])}",
                severity="critical",
                cvss=9.8,
                confidence="medium",
                family="xml_injection",
                subtype="xxe_oob",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"oob_patterns": oob_matches[:3]},
            )

        if resp["status_code"] != baseline["status_code"] and resp["status_code"] in (403, 500):
            return self._create_finding(
                title="XML Injection - XXE OOB (Blocked)",
                description=f"XXE OOB payload caused {resp['status_code']} error, potentially blocked by WAF.",
                severity="medium",
                cvss=6.5,
                confidence="low",
                family="xml_injection",
                subtype="xxe_oob",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"waf_blocked": True},
            )
        return None

    async def _test_xslt_injection(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        xslt_matches = self._match_patterns(body, XSLT_PATTERNS)
        exploit_matches = self._match_patterns(body, XSLT_EXPLOIT_INDICATORS)

        if exploit_matches:
            return self._create_finding(
                title="XML Injection - XSLT Injection (RCE)",
                description=f"XSLT injection with code execution detected: {', '.join(exploit_matches[:3])}",
                severity="critical",
                cvss=10.0,
                confidence="high",
                family="xml_injection",
                subtype="xslt_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"exploit_indicators": exploit_matches[:5]},
            )

        if xslt_matches:
            return self._create_finding(
                title="XML Injection - XSLT Injection",
                description=f"XSLT injection detected. XSLT processing evidence: {', '.join(xslt_matches[:3])}",
                severity="high",
                cvss=8.6,
                confidence="medium",
                family="xml_injection",
                subtype="xslt_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"xslt_patterns": xslt_matches[:5]},
            )
        return None
