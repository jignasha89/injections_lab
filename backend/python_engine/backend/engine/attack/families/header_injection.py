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

CRLF_PATTERNS = [
    r"%0d%0a",
    r"%0D%0A",
    r"%0d%0a%0d%0a",
    r"\\r\\n",
    r"\\r\\n\\r\\n",
    r"\r\n",
    r"\r\n\r\n",
    r"Set-Cookie:.*?evil",
    r"Set-Cookie:.*?admin",
    r"Set-Cookie:.*?session",
    r"X-Injected:.*?true",
]

HOST_HEADER_INJECTION_PATTERNS = [
    r"X-Forwarded-Host:.*?evil",
    r"Host:.*?evil\.com",
    r"X-Host:.*?evil\.com",
    r"X-Forwarded-For:.*?127\.0\.0\.1",
    r"Forwarded:.*?host=",
    r"X-Original-URL",
    r"X-Rewrite-URL",
]

CACHE_POISONING_PATTERNS = [
    r"Age:\s*\d+",
    r"X-Cache:.*?HIT",
    r"Via:.*?cache",
    r"Cache-Control:.*?public",
    r"Vary:.*?Host",
    r"X-Varnish",
    r"X-Cache-Hits",
]

HTTP_HEADER_INJECTION_PATTERNS = [
    r"X-Injected-Header:.*?true",
    r"X-Debug:.*?true",
    r"X-Custom-Header:.*?injected",
    r"Authorization:.*?Basic",
    r"Cookie:.*?admin=true",
    r"Set-Cookie:.*?injected",
]

EMAIL_HEADER_PATTERNS = [
    r"To:.*?evil",
    r"CC:.*?evil",
    r"BCC:.*?evil",
    r"Subject:.*?injected",
    r"From:.*?evil",
    r"Reply-To:.*?evil",
    r"MIME-Version:.*?1\.0",
    r"Content-Type:.*?multipart",
    r"boundary=.*?evil",
]


class HeaderInjectionScanner:
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
            logger.error(f"Header injection baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "crlf")
            payload_str = payload.get("payload_string", "")

            if subtype == "crlf":
                result = await self._test_crlf(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "host_header":
                result = await self._test_host_header(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "http_header":
                result = await self._test_http_header(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "email_header":
                result = await self._test_email_header(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_crlf(
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

    async def _send_header_payload(
        self, url: str, method: str, header_name: str, payload: str
    ) -> dict:
        start = time.time()
        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout, follow_redirects=True
            ) as client:
                headers = {header_name: payload}
                if method == "GET":
                    resp = await client.get(url, headers=headers)
                else:
                    resp = await client.post(url, headers=headers, data={"test": "value"})
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

    def _check_header_in_response(self, headers: dict, pattern: str) -> bool:
        for key, value in headers.items():
            if re.search(pattern, f"{key}: {value}", re.IGNORECASE):
                return True
        return False

    async def _test_crlf(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        headers = resp["headers"]
        crlf_matched = False

        for key, value in headers.items():
            combined = f"{key}: {value}"
            for pattern in CRLF_PATTERNS:
                if re.search(pattern, combined, re.IGNORECASE):
                    crlf_matched = True
                    break

        if "\r\n" in payload or "%0d%0a" in payload.lower():
            new_headers = {k: v for k, v in headers.items() if k.lower() not in ("content-type", "content-length")}
            for key, value in new_headers.items():
                for pattern in CRLF_PATTERNS:
                    if re.search(pattern, f"{key}: {value}", re.IGNORECASE):
                        crlf_matched = True
                        break

        if crlf_matched or (resp["status_code"] != baseline["status_code"] and any(
            cp in payload.lower() for cp in ["%0d%0a", "\\r\\n", "\r\n"]
        )):
            return self._create_finding(
                title="HTTP Header Injection - CRLF",
                description="CRLF injection detected. Response headers contain injected content.",
                severity="high",
                cvss=7.4,
                confidence="high",
                family="header_injection",
                subtype="crlf",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "headers_injected": True},
                evidence={"crlf_detected": True, "injected_headers": list(headers.keys())[:5]},
            )

        if payload in body and any(cp in payload for cp in ["%0d%0a", "\\r\\n", "\r\n"]):
            return self._create_finding(
                title="HTTP Header Injection - CRLF (Reflected)",
                description="CRLF payload reflected in response body.",
                severity="medium",
                cvss=6.1,
                confidence="medium",
                family="header_injection",
                subtype="crlf",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"payload_reflected": True},
            )
        return None

    async def _test_host_header(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_header_payload(url, method, "Host", payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        headers = resp["headers"]

        host_injected = any(
            payload.lower() in f"{k}: {v}".lower()
            for k, v in headers.items()
        )

        cache_poisoned = any(
            re.search(pattern, f"{k}: {v}", re.IGNORECASE)
            for k, v in headers.items()
            for pattern in CACHE_POISONING_PATTERNS
        )

        if host_injected or cache_poisoned:
            return self._create_finding(
                title="HTTP Header Injection - Host Header",
                description="Host header injection detected. Modified Host header accepted by server.",
                severity="high",
                cvss=7.4,
                confidence="high",
                family="header_injection",
                subtype="host_header",
                payload=payload,
                request_data={"url": url, "method": method, "header": "Host", "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"host_injected": host_injected, "cache_poisoning": cache_poisoned},
            )

        if resp["status_code"] != baseline["status_code"]:
            return self._create_finding(
                title="HTTP Header Injection - Host Header (Anomaly)",
                description="Host header modification caused status code change.",
                severity="medium",
                cvss=6.1,
                confidence="medium",
                family="header_injection",
                subtype="host_header",
                payload=payload,
                request_data={"url": url, "method": method, "header": "Host", "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"status_change": True},
            )
        return None

    async def _test_http_header(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        header_name = param_name if param_name.startswith("X-") else "X-Injected-Header"
        resp = await self._send_header_payload(url, method, header_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        headers = resp["headers"]

        header_patterns = HTTP_HEADER_INJECTION_PATTERNS
        matched = self._match_patterns(body, header_patterns)

        for key, value in headers.items():
            combined = f"{key}: {value}"
            for pattern in header_patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    matched.append(pattern)

        if matched:
            return self._create_finding(
                title="HTTP Header Injection",
                description=f"HTTP header injection detected. Patterns: {', '.join(matched[:3])}",
                severity="medium",
                cvss=6.1,
                confidence="medium",
                family="header_injection",
                subtype="http_header",
                payload=payload,
                request_data={"url": url, "method": method, "header": header_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"matched_patterns": matched[:5]},
            )

        if resp["status_code"] != baseline["status_code"]:
            return self._create_finding(
                title="HTTP Header Injection (Anomaly)",
                description="Custom header injection caused status code change.",
                severity="low",
                cvss=3.7,
                confidence="low",
                family="header_injection",
                subtype="http_header",
                payload=payload,
                request_data={"url": url, "method": method, "header": header_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"anomaly": True},
            )
        return None

    async def _test_email_header(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matched = self._match_patterns(body, EMAIL_HEADER_PATTERNS)

        if matched:
            return self._create_finding(
                title="HTTP Header Injection - Email",
                description=f"Email header injection detected: {', '.join(matched[:3])}",
                severity="medium",
                cvss=6.1,
                confidence="medium",
                family="header_injection",
                subtype="email_header",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"email_patterns": matched[:5]},
            )

        if payload in body and any(ep in payload.lower() for ep in ["to:", "cc:", "bcc:", "subject:"]):
            return self._create_finding(
                title="HTTP Header Injection - Email (Reflected)",
                description="Email header payload reflected in response.",
                severity="medium",
                cvss=5.3,
                confidence="medium",
                family="header_injection",
                subtype="email_header",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"email_payload_reflected": True},
            )
        return None
