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

SMTP_PATTERNS = [
    r"220.*?SMTP",
    r"250.*?OK",
    r"250.*?mail",
    r"250.*?rcpt",
    r"354.*?Start mail input",
    r"221.*?Bye",
    r"550.*?User unknown",
    r"553.*?Mailbox name not allowed",
    r"421.*?Service not available",
    r"SMTP.*?error",
    r"mail.*?from:",
    r"rcpt.*?to:",
]

IMAP_PATTERNS = [
    r"\* OK",
    r"\* PREAUTH",
    r"CAPABILITY",
    r"LOGIN",
    r"SELECT.*?INBOX",
    r"FETCH",
    r"SEARCH",
    r"LOGOUT",
    r"NO.*?Invalid",
    r"BAD.*?Command",
    r"IMAP.*?error",
]

FTP_PATTERNS = [
    r"220.*?FTP",
    r"230.*?Logged in",
    r"331.*?Password required",
    r"530.*?Login incorrect",
    r"USER",
    r"PASS",
    r"LIST",
    r"RETR",
    r"STOR",
    r"CWD",
    r"PWD",
    r"PASV",
    r"211.*?Features",
    r"215.*?Type",
]

SMUGGLING_PATTERNS_CL_TE = [
    r"Transfer-Encoding:\s*chunked",
    r"Content-Length:\s*\d+",
    r"\r\n\r\n",
    r"0\r\n\r\n",
    r"Content-Encoding",
]

SMUGGLING_PATTERNS_TE_CL = [
    r"Transfer-Encoding:\s*identity",
    r"Transfer-Encoding:\s*chunked",
    r"Content-Length:\s*\d+",
    r"\d+\r\n",
    r"\r\n0\r\n",
]

SMUGGLING_PATTERNS_TE_TE = [
    r"Transfer-Encoding:\s*chunked",
    r"Transfer-Encoding:\s*",
    r"Transfer-Encoding:\s*x",
    r"Transfer-Encoding:\s*identity,.*?chunked",
    r"Transfer-Encoding:\s*chunked,.*?identity",
]

SMUGGLING_RESPONSE_PATTERNS = [
    r"HTTP/1\.\d\s+\d+",
    r"Connection:.*?close",
    r"Transfer-Encoding:.*?chunked",
    r"Content-Length:.*?\d+",
]


class ProtocolInjectionScanner:
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
            logger.error(f"Protocol injection baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "smtp")
            payload_str = payload.get("payload_string", "")

            if subtype == "smtp":
                result = await self._test_smtp(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "imap":
                result = await self._test_imap(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "ftp":
                result = await self._test_ftp(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "http_request_smuggling":
                result = await self._test_http_smuggling(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_smtp(
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

    async def _send_raw_request(self, url: str, raw_data: str) -> dict:
        start = time.time()
        try:
            parsed = urlparse(url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or 80

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )
            writer.write(raw_data.encode())
            await writer.drain()

            response_data = b""
            try:
                response_data = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                pass

            writer.close()
            await writer.wait_closed()

            elapsed = time.time() - start
            body = response_data.decode("utf-8", errors="ignore")
            return {
                "status_code": 200 if body else 0,
                "body": body,
                "body_length": len(body),
                "response_time": elapsed,
                "headers": {},
                "error": None,
            }
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

    async def _test_smtp(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, SMTP_PATTERNS)

        if matches:
            return self._create_finding(
                title="Protocol Injection - SMTP",
                description=f"SMTP protocol injection detected: {', '.join(matches[:3])}",
                severity="high",
                cvss=8.1,
                confidence="high",
                family="protocol_injection",
                subtype="smtp",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"smtp_patterns": matches[:5]},
            )

        if any(sp in payload.lower() for sp in ["smtp", "mail from", "rcpt to", "data"]) and resp["status_code"] != baseline["status_code"]:
            return self._create_finding(
                title="Protocol Injection - SMTP (Anomaly)",
                description="SMTP payload caused status code anomaly.",
                severity="medium",
                cvss=6.5,
                confidence="medium",
                family="protocol_injection",
                subtype="smtp",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"smtp_anomaly": True},
            )
        return None

    async def _test_imap(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, IMAP_PATTERNS)

        if matches:
            return self._create_finding(
                title="Protocol Injection - IMAP",
                description=f"IMAP protocol injection detected: {', '.join(matches[:3])}",
                severity="high",
                cvss=8.1,
                confidence="high",
                family="protocol_injection",
                subtype="imap",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"imap_patterns": matches[:5]},
            )
        return None

    async def _test_ftp(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, FTP_PATTERNS)

        if matches:
            return self._create_finding(
                title="Protocol Injection - FTP",
                description=f"FTP protocol injection detected: {', '.join(matches[:3])}",
                severity="high",
                cvss=8.1,
                confidence="high",
                family="protocol_injection",
                subtype="ftp",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"ftp_patterns": matches[:5]},
            )
        return None

    async def _test_http_smuggling(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        headers = resp["headers"]
        smuggling_type = None

        te_headers = [v for k, v in headers.items() if k.lower() == "transfer-encoding"]
        cl_headers = [v for k, v in headers.items() if k.lower() == "content-length"]

        if te_headers and cl_headers:
            smuggling_type = "CL.TE"
            te_cl_matches = self._match_patterns(body, SMUGGLING_PATTERNS_CL_TE + SMUGGLING_PATTERNS_TE_CL)
            if te_cl_matches:
                return self._create_finding(
                    title="Protocol Injection - HTTP Request Smuggling (CL.TE)",
                    description="HTTP request smuggling (CL.TE) detected. Both Transfer-Encoding and Content-Length headers present.",
                    severity="critical",
                    cvss=9.1,
                    confidence="medium",
                    family="protocol_injection",
                    subtype="http_request_smuggling",
                    payload=payload,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                    response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                    evidence={"smuggling_type": "CL.TE", "matched_patterns": te_cl_matches[:3]},
                )

        te_count = len(te_headers)
        if te_count > 1:
            smuggling_type = "TE.TE"
            te_te_matches = self._match_patterns(body, SMUGGLING_PATTERNS_TE_TE)
            if te_te_matches:
                return self._create_finding(
                    title="Protocol Injection - HTTP Request Smuggling (TE.TE)",
                    description="HTTP request smuggling (TE.TE) detected. Multiple Transfer-Encoding headers present.",
                    severity="critical",
                    cvss=9.1,
                    confidence="medium",
                    family="protocol_injection",
                    subtype="http_request_smuggling",
                    payload=payload,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                    response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                    evidence={"smuggling_type": "TE.TE", "te_headers": te_count},
                )

        if payload in body and ("transfer-encoding" in payload.lower() or "content-length" in payload.lower()):
            return self._create_finding(
                title="Protocol Injection - HTTP Smuggling (Payload Reflected)",
                description="HTTP smuggling payload reflected in response.",
                severity="high",
                cvss=7.5,
                confidence="medium",
                family="protocol_injection",
                subtype="http_request_smuggling",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"payload_reflected": True},
            )

        if resp["status_code"] != baseline["status_code"] and resp["status_code"] in (400, 403, 502, 503):
            return self._create_finding(
                title="Protocol Injection - HTTP Smuggling (Anomaly)",
                description=f"HTTP smuggling attempt caused {resp['status_code']} error.",
                severity="medium",
                cvss=6.5,
                confidence="low",
                family="protocol_injection",
                subtype="http_request_smuggling",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"smuggling_anomaly": True},
            )
        return None
