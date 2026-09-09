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

LOG_INJECTION_PATTERNS = [
    r"CRLF.*?injection",
    r"log.*?injection",
    r"newline.*?injection",
    r"\\r\\n",
    r"%0d%0a",
    r"%0A",
    r"%0D",
    r"\r\n",
    r"\\n",
    r"line.*?break",
]

LOG4SHELL_PATTERNS = [
    r"\$\{jndi:",
    r"\$\{env:",
    r"\$\{lower:",
    r"\$\{upper:",
    r"\$\{::-",
    r"\$\{sys:",
    r"\$\{file:",
    r"\$\{date:",
    r"\$\{log:",
    r"jndi:ldap",
    "jndi:rmi",
    "jndi:dns",
    r"lookup.*?jndi",
    r"jndi.*?lookup",
]

CSS_INJECTION_PATTERNS = [
    r"expression\(",
    r"url\(.*?javascript:",
    r"url\(.*?data:",
    r"@import",
    r"@font-face",
    r"behavior:",
    r"-moz-binding:",
    r"background.*?url\(.*?data:",
    r"content.*?url\(.*?data:",
    r"filter.*?url\(.*?data:",
]

HTML_INJECTION_PATTERNS = [
    r"<script",
    r"<img.*?src",
    r"<iframe",
    r"<object",
    r"<embed",
    r"<svg",
    r"<link.*?rel.*?stylesheet",
    r"<base.*?href",
    r"<form.*?action",
    r"<meta.*?http-equiv",
    r"javascript:",
    r"data:text/html",
]

SSI_PATTERNS = [
    r"<!--#exec",
    r"<!--#include",
    r"<!--#echo",
    r"<!--#config",
    r"<!--#fsize",
    r"<!--#flastmod",
    r"<!--#printenv",
    r"<!--#cgi",
    r"<!--#include.*?virtual",
    r"<!--#include.*?file",
    r"<!--#set",
    r"<!--#if",
]

FORMULA_CSV_PATTERNS = [
    r"=SUM\(",
    r"=AVERAGE\(",
    r"=MAX\(",
    r"=MIN\(",
    r"=COUNT\(",
    r"=IF\(",
    r"=VLOOKUP\(",
    r"=HYPERLINK\(",
    r"=SYSTEM\(",
    r"=EXEC\(",
    r"=SHELL\(",
    r"\|.*?cmd",
    r"\|.*?sh ",
    r"`.*?`",
    r"\$\(.*?\)",
    r"cmd\.exe",
    r"/bin/sh",
]

PDF_INJECTION_PATTERNS = [
    r"/JavaScript",
    r"/JS\s",
    r"/OpenAction",
    r"/AA\s",
    r"/Launch",
    r"/RichMediaExecute",
    r"/XFA",
    r"/AcroForm",
    r"/NeedAppearances",
    r"/SubmitForm",
    r"/ImportData",
    r"/JBIG2Decode",
    r"/RichMediaExecute",
    r"/Font.*?Type1",
]

REDOSS_PATTERNS = [
    r"(a+)+",
    r"(a|a)+",
    r"(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z)+",
    r"(a|b)+",
    r"(a|ab)+",
    r"(a|a?b)+",
    r"(a|aa)+",
    r"(a|aaa)+",
]


class AppLoggingInjectionScanner:
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
            logger.error(f"App/Logging injection baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "log_injection")
            payload_str = payload.get("payload_string", "")

            if subtype == "log_injection":
                result = await self._test_log_injection(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "log4shell":
                result = await self._test_log4shell(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "css_injection":
                result = await self._test_css_injection(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "html_injection":
                result = await self._test_html_injection(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "ssi":
                result = await self._test_ssi(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "formula_csv":
                result = await self._test_formula_csv(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "pdf_injection":
                result = await self._test_pdf_injection(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "redos":
                result = await self._test_redos(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_log_injection(
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

    async def _test_log_injection(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, LOG_INJECTION_PATTERNS)

        if matches:
            return self._create_finding(
                title="App/Logging - Log Injection",
                description=f"Log injection detected. Newline/CRLF injection in log output: {', '.join(matches[:3])}",
                severity="medium",
                cvss=6.1,
                confidence="medium",
                family="app_logging_injection",
                subtype="log_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"log_injection_patterns": matches[:5]},
            )
        return None

    async def _test_log4shell(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, LOG4SHELL_PATTERNS)

        if matches:
            return self._create_finding(
                title="App/Logging - Log4Shell",
                description=f"Log4Shell (CVE-2021-44228) vulnerability detected. JNDI lookup in payload: {', '.join(matches[:3])}",
                severity="critical",
                cvss=10.0,
                confidence="high",
                family="app_logging_injection",
                subtype="log4shell",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"log4shell_patterns": matches[:5], "jndi_lookup": True},
            )

        if "${jndi:" in payload and resp["status_code"] == 500:
            return self._create_finding(
                title="App/Logging - Log4Shell (Error)",
                description="Log4Shell payload caused 500 error, potentially indicating vulnerable Log4j.",
                severity="high",
                cvss=9.1,
                confidence="medium",
                family="app_logging_injection",
                subtype="log4shell",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"status_500": True},
            )
        return None

    async def _test_css_injection(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, CSS_INJECTION_PATTERNS)

        if matches:
            return self._create_finding(
                title="App/Logging - CSS Injection",
                description=f"CSS injection detected: {', '.join(matches[:3])}",
                severity="medium",
                cvss=6.1,
                confidence="medium",
                family="app_logging_injection",
                subtype="css_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"css_patterns": matches[:5]},
            )

        if payload in body and ("url(" in payload or "expression(" in payload):
            return self._create_finding(
                title="App/Logging - CSS Injection (Reflected)",
                description="CSS injection payload reflected in response.",
                severity="medium",
                cvss=5.3,
                confidence="medium",
                family="app_logging_injection",
                subtype="css_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"payload_reflected": True},
            )
        return None

    async def _test_html_injection(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, HTML_INJECTION_PATTERNS)

        if matches:
            return self._create_finding(
                title="App/Logging - HTML Injection",
                description=f"HTML injection detected: {', '.join(matches[:3])}",
                severity="medium",
                cvss=5.3,
                confidence="medium",
                family="app_logging_injection",
                subtype="html_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"html_patterns": matches[:5]},
            )

        if payload in body and "<" in payload and ">" in payload:
            return self._create_finding(
                title="App/Logging - HTML Injection (Reflected)",
                description="HTML payload reflected in response.",
                severity="low",
                cvss=3.7,
                confidence="low",
                family="app_logging_injection",
                subtype="html_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"payload_reflected": True},
            )
        return None

    async def _test_ssi(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, SSI_PATTERNS)

        if matches:
            return self._create_finding(
                title="App/Logging - SSI Injection",
                description=f"Server-Side Includes (SSI) injection detected: {', '.join(matches[:3])}",
                severity="high",
                cvss=8.1,
                confidence="high",
                family="app_logging_injection",
                subtype="ssi",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"ssi_patterns": matches[:5]},
            )
        return None

    async def _test_formula_csv(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, FORMULA_CSV_PATTERNS)

        if matches:
            return self._create_finding(
                title="App/Logging - Formula/CSV Injection",
                description=f"Formula/CSV injection detected: {', '.join(matches[:3])}",
                severity="medium",
                cvss=6.1,
                confidence="high",
                family="app_logging_injection",
                subtype="formula_csv",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"formula_patterns": matches[:5]},
            )

        if payload in body and any(fp in payload for fp in ["=", "|", "`", "$("]):
            return self._create_finding(
                title="App/Logging - Formula/CSV Injection (Reflected)",
                description="Formula/CSV injection payload reflected.",
                severity="medium",
                cvss=5.3,
                confidence="medium",
                family="app_logging_injection",
                subtype="formula_csv",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"payload_reflected": True},
            )
        return None

    async def _test_pdf_injection(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, PDF_INJECTION_PATTERNS)

        if matches:
            return self._create_finding(
                title="App/Logging - PDF Injection",
                description=f"PDF injection detected: {', '.join(matches[:3])}",
                severity="high",
                cvss=7.5,
                confidence="high",
                family="app_logging_injection",
                subtype="pdf_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"pdf_patterns": matches[:5]},
            )
        return None

    async def _test_redos(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        start = time.time()
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            if "timeout" in resp.get("error", "").lower():
                return self._create_finding(
                    title="App/Logging - Regex ReDoS",
                    description="Regular Expression Denial of Service (ReDoS) detected. Payload caused timeout.",
                    severity="high",
                    cvss=7.5,
                    confidence="high",
                    family="app_logging_injection",
                    subtype="redos",
                    payload=payload,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                    response_data={"response_time": resp["response_time"]},
                    evidence={"timeout": True, "redos": True},
                )
            return None

        response_time = resp["response_time"]
        baseline_time = baseline["response_time"]
        time_ratio = response_time / max(baseline_time, 0.001)

        if time_ratio > 5.0 and response_time > 5.0:
            return self._create_finding(
                title="App/Logging - Regex ReDoS",
                description=f"ReDoS detected. Response time {time_ratio:.1f}x slower than baseline ({response_time:.1f}s vs {baseline_time:.1f}s).",
                severity="high",
                cvss=7.5,
                confidence="high",
                family="app_logging_injection",
                subtype="redos",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"response_time": response_time, "baseline_time": baseline_time},
                evidence={"time_ratio": time_ratio, "redos": True},
            )

        for redos_pattern in REDOSS_PATTERNS:
            if redos_pattern in payload:
                time_multiplier = response_time / max(baseline_time, 0.001)
                if time_multiplier > 2.0:
                    return self._create_finding(
                        title="App/Logging - Regex ReDoS (Pattern)",
                        description=f"ReDoS pattern detected: {redos_pattern}. Time multiplier: {time_multiplier:.1f}x.",
                        severity="medium",
                        cvss=6.5,
                        confidence="medium",
                        family="app_logging_injection",
                        subtype="redos",
                        payload=payload,
                        request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                        response_data={"response_time": response_time},
                        evidence={"redos_pattern": redos_pattern, "time_multiplier": time_multiplier},
                    )
        return None
