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

PATH_TRAVERSAL_LINUX_PATTERNS = [
    r"root:x:0:0",
    r"daemon:",
    r"bin:",
    r"sys:",
    r"adm:",
    r"tty:",
    r"disk:",
    r"lp:",
    r"mail:",
    r"news:",
    r"uucp:",
    r"proxy:",
    r"www-data:",
    r"backup:",
    r"list:",
    r"irc:",
    r"gnats:",
    r"nobody:",
    r"systemd-network:",
    r"dbus:",
    r"polkitd:",
    r"sshd:",
    r"postfix:",
    r"chrony:",
    r"/bin/bash",
    r"/bin/sh",
    r"/bin/false",
    r"/sbin/nologin",
]

PATH_TRAVERSAL_WINDOWS_PATTERNS = [
    r"\[boot loader\]",
    r"\[operating systems\]",
    r"Windows IP Configuration",
    r"nt authority\\system",
    r" administrators",
    r"C:\\Windows",
    r"C:\\Users",
    r"C:\\Program Files",
    r"Volume Serial Number",
    r"\[fonts\]",
    r"\[extensions\]",
    r"\[mci extensions\]",
    r"\[mail\]",
    r"boot\.ini",
    r"win\.ini",
    r"system\.ini",
    r"protocol\.ini",
]

NULL_BYTE_PATTERNS = [
    r"%00",
    r"\\x00",
    r"\\0",
    r"\x00",
]

UNICODE_BYPASS_PATTERNS = [
    r"%c0%ae",
    r"%c1%9c",
    r"%e0%80%af",
    r"%f0%80%80%af",
    r"%2e%2e",
    r"%252e%252e",
    r"%252f",
    r"%c0%af",
    r"%c1%9c",
]

CONFIG_FILE_PATTERNS = [
    r"database.*?password",
    r"db_pass",
    r"mysql.*?root",
    r"postgres",
    r"redis.*?requirepass",
    r"smtp.*?pass",
    r"api_key",
    r"secret_key",
    r"private_key",
    r"aws_access_key",
    r"aws_secret_key",
    r"credentials",
    r"password\s*[=:]\s*\S+",
]


class PathTraversalScanner:
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
            logger.error(f"Path traversal baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "linux")
            payload_str = payload.get("payload_string", "")

            if subtype == "linux":
                result = await self._test_linux_traversal(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "windows":
                result = await self._test_windows_traversal(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "null_byte":
                result = await self._test_null_byte(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "unicode_bypass":
                result = await self._test_unicode_bypass(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_linux_traversal(
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

    async def _test_linux_traversal(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        file_matches = self._match_patterns(body, PATH_TRAVERSAL_LINUX_PATTERNS)
        config_matches = self._match_patterns(body, CONFIG_FILE_PATTERNS)

        if file_matches:
            severity = "critical" if config_matches else "high"
            return self._create_finding(
                title="Path Traversal - Linux File Access",
                description=f"Linux path traversal detected. File content leaked: {', '.join(file_matches[:3])}",
                severity=severity,
                cvss=9.1 if config_matches else 7.5,
                confidence="high",
                family="path_traversal",
                subtype="linux",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"file_patterns": file_matches[:5], "config_leaked": bool(config_matches)},
            )

        if resp["body_length"] > baseline["body_length"] * 1.5 and ".." in payload:
            return self._create_finding(
                title="Path Traversal - Linux (Anomaly)",
                description="Path traversal attempt caused significant response body change.",
                severity="medium",
                cvss=6.5,
                confidence="medium",
                family="path_traversal",
                subtype="linux",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"body_length_change": True},
            )
        return None

    async def _test_windows_traversal(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        file_matches = self._match_patterns(body, PATH_TRAVERSAL_WINDOWS_PATTERNS)
        config_matches = self._match_patterns(body, CONFIG_FILE_PATTERNS)

        if file_matches:
            severity = "critical" if config_matches else "high"
            return self._create_finding(
                title="Path Traversal - Windows File Access",
                description=f"Windows path traversal detected. File content leaked: {', '.join(file_matches[:3])}",
                severity=severity,
                cvss=9.1 if config_matches else 7.5,
                confidence="high",
                family="path_traversal",
                subtype="windows",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"file_patterns": file_matches[:5], "config_leaked": bool(config_matches)},
            )
        return None

    async def _test_null_byte(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        all_patterns = PATH_TRAVERSAL_LINUX_PATTERNS + PATH_TRAVERSAL_WINDOWS_PATTERNS + CONFIG_FILE_PATTERNS
        file_matches = self._match_patterns(body, all_patterns)

        if file_matches:
            return self._create_finding(
                title="Path Traversal - Null Byte",
                description=f"Null byte path traversal detected. Null byte bypassed file extension check: {', '.join(file_matches[:3])}",
                severity="high",
                cvss=8.1,
                confidence="high",
                family="path_traversal",
                subtype="null_byte",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"file_patterns": file_matches[:5], "null_byte_bypass": True},
            )

        if any(nb in payload for nb in NULL_BYTE_PATTERNS) and resp["status_code"] != baseline["status_code"]:
            return self._create_finding(
                title="Path Traversal - Null Byte (Anomaly)",
                description="Null byte payload caused status code anomaly.",
                severity="medium",
                cvss=6.5,
                confidence="medium",
                family="path_traversal",
                subtype="null_byte",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"null_byte_anomaly": True},
            )
        return None

    async def _test_unicode_bypass(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        all_patterns = PATH_TRAVERSAL_LINUX_PATTERNS + PATH_TRAVERSAL_WINDOWS_PATTERNS + CONFIG_FILE_PATTERNS
        file_matches = self._match_patterns(body, all_patterns)

        if file_matches:
            return self._create_finding(
                title="Path Traversal - Unicode Bypass",
                description=f"Unicode path traversal bypass detected. Filter bypass confirmed: {', '.join(file_matches[:3])}",
                severity="high",
                cvss=8.1,
                confidence="high",
                family="path_traversal",
                subtype="unicode_bypass",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"file_patterns": file_matches[:5], "unicode_bypass": True},
            )

        has_unicode = any(ub in payload for ub in UNICODE_BYPASS_PATTERNS)
        if has_unicode and resp["status_code"] != baseline["status_code"]:
            return self._create_finding(
                title="Path Traversal - Unicode Bypass (Anomaly)",
                description="Unicode bypass payload caused status code anomaly.",
                severity="medium",
                cvss=6.5,
                confidence="low",
                family="path_traversal",
                subtype="unicode_bypass",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"unicode_anomaly": True},
            )
        return None
