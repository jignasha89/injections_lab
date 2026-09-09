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

LDAP_ERROR_PATTERNS = [
    r"ldap_search",
    r"LDAP error",
    r"invalid credentials",
    r"operations error",
    r"protocol error",
    r"unavailable critical extension",
    r"naming violation",
    r"object class violation",
    r"no such object",
    r"invalid DN syntax",
    r"ldap_bind",
    r"ldap_modify",
    r"ldap_add",
    r"ldap_delete",
    r"size limit exceeded",
    r"time limit exceeded",
    r"administrative limit exceeded",
    r"inappropriate authentication",
    r"invalid attribute syntax",
    r"undefined attribute type",
    r"LDAPResult",
]

XML_ERROR_PATTERNS = [
    r"XML parsing error",
    r" SAXParseException",
    r"xml\.sax\.SAXParseException",
    r"lxml\.etree",
    r"ElementTree",
    r"XMLSyntaxError",
    r"not well-formed",
    r"Content is not allowed in prolog",
    r"markup declarations must be properly nested",
    r"xml parser",
    r"XML document",
    r"DOMException",
    r"SAXParser",
    r"XMLReader",
]

XPATH_BOOLEAN_PATTERNS = [
    r"true",
    r"false",
    r"1",
    r"0",
    r"boolean",
    r"string",
    r"number",
    r"node-set",
]

XPATH_ERROR_PATTERNS = [
    r"XPathError",
    r"xpath\.XPathEvalError",
    r"lxml\.etree\.XPathSyntaxError",
    r"Invalid XPath",
    r"invalid predicate",
    r"unexpected end of expression",
    r"Invalid expression",
    r"Undefined variable",
    r"xpath\.XPath",
    r"NodeSet",
    r"XPathResult",
]

XQUERY_PATTERNS = [
    r"XQuery",
    r"XQST",
    r"err:XPST",
    r"err:FORG",
    r"err:FODT",
    r"basex",
    r"eXist",
    r"MarkLogic",
    r"xml数据库",
]


class DirectoryInjectionScanner:
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
            logger.error(f"Directory injection baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "ldap")
            payload_str = payload.get("payload_string", "")

            if subtype == "ldap":
                result = await self._test_ldap(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "xml":
                result = await self._test_xml_injection(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "xpath_boolean":
                result = await self._test_xpath_boolean(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "xpath_error":
                result = await self._test_xpath_error(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "blind_xpath":
                result = await self._test_blind_xpath(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "xquery":
                result = await self._test_xquery(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_ldap(
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

    async def _test_ldap(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, LDAP_ERROR_PATTERNS)

        if matches:
            return self._create_finding(
                title="Directory Injection - LDAP",
                description=f"LDAP injection detected. Error patterns found: {', '.join(matches[:3])}",
                severity="high",
                cvss=8.6,
                confidence="high",
                family="directory_injection",
                subtype="ldap",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:5]},
            )

        if payload in body or ("ldap" in body.lower() and resp["status_code"] != baseline["status_code"]):
            return self._create_finding(
                title="Directory Injection - LDAP (Anomaly)",
                description="LDAP injection attempt caused response anomaly.",
                severity="high",
                cvss=7.5,
                confidence="medium",
                family="directory_injection",
                subtype="ldap",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"anomaly_detected": True},
            )
        return None

    async def _test_xml_injection(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, XML_ERROR_PATTERNS)

        if matches:
            return self._create_finding(
                title="Directory Injection - XML",
                description=f"XML injection detected. Error patterns: {', '.join(matches[:3])}",
                severity="high",
                cvss=8.1,
                confidence="high",
                family="directory_injection",
                subtype="xml",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:5]},
            )

        if "<" in payload and ">" in payload and resp["status_code"] != baseline["status_code"]:
            return self._create_finding(
                title="Directory Injection - XML (Anomaly)",
                description="XML payload caused status code change.",
                severity="medium",
                cvss=6.5,
                confidence="low",
                family="directory_injection",
                subtype="xml",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"status_change": True},
            )
        return None

    async def _test_xpath_boolean(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        body_lower = body.lower()

        true_indicators = ["true", "1", "yes", "admin"]
        false_indicators = ["false", "0", "no", "invalid"]

        is_true_like = any(ind in body_lower for ind in true_indicators)
        is_false_like = any(ind in body_lower for ind in false_indicators)

        if "true" in payload.lower() and is_true_like and not is_false_like:
            return self._create_finding(
                title="Directory Injection - XPath Boolean",
                description="XPath boolean-based injection detected. True condition produced different response.",
                severity="high",
                cvss=8.6,
                confidence="high",
                family="directory_injection",
                subtype="xpath_boolean",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"condition": "true", "response_pattern": is_true_like},
            )

        if "false" in payload.lower() and is_false_like and not is_true_like:
            return self._create_finding(
                title="Directory Injection - XPath Boolean",
                description="XPath boolean-based injection detected. False condition produced different response.",
                severity="high",
                cvss=8.6,
                confidence="high",
                family="directory_injection",
                subtype="xpath_boolean",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"condition": "false", "response_pattern": is_false_like},
            )
        return None

    async def _test_xpath_error(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, XPATH_ERROR_PATTERNS)

        if matches:
            return self._create_finding(
                title="Directory Injection - XPath Error-Based",
                description=f"XPath error-based injection detected. Error patterns: {', '.join(matches[:3])}",
                severity="high",
                cvss=8.6,
                confidence="high",
                family="directory_injection",
                subtype="xpath_error",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:5]},
            )
        return None

    async def _test_blind_xpath(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body_length_diff = abs(resp["body_length"] - baseline["body_length"])
        time_diff = abs(resp["response_time"] - baseline["response_time"])

        if body_length_diff > 50 or time_diff > 2.0:
            return self._create_finding(
                title="Directory Injection - Blind XPath",
                description="Blind XPath injection detected. Response anomaly observed.",
                severity="high",
                cvss=8.1,
                confidence="medium",
                family="directory_injection",
                subtype="blind_xpath",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length_diff": body_length_diff, "time_diff": time_diff},
                evidence={"body_length_diff": body_length_diff, "time_diff": time_diff},
            )
        return None

    async def _test_xquery(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, XQUERY_PATTERNS)

        if matches:
            return self._create_finding(
                title="Directory Injection - XQuery",
                description=f"XQuery injection detected. Database errors: {', '.join(matches[:3])}",
                severity="high",
                cvss=8.6,
                confidence="high",
                family="directory_injection",
                subtype="xquery",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:3]},
            )
        return None
