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

SSRF_INTERNAL_IPS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.1.1",
    "http://169.254.169.254",
    "http://metadata.google.internal",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
]

CLOUD_METADATA_PATTERNS = [
    r"ami-id",
    r"instance-id",
    r"instance-type",
    r"local-ipv4",
    r"security-credentials",
    r"iam.*?role",
    r"user-data",
    r"base64",
    r"metadata",
    r"ec2",
    r"gce",
    r"azure",
    r"instance.*?identity",
]

SSRF_FILE_PATTERNS = [
    r"root:x:0:0",
    r"\[boot loader\]",
    r"daemon:",
    r"/bin/bash",
    r"/bin/sh",
    r"windows",
    r"nt authority",
    r"/etc/passwd",
    r"/etc/hostname",
    r"php\.ini",
    r"web\.xml",
]

SSRF_DNS_REBIND_PATTERNS = [
    r"rebind",
    r"dns.*?rebind",
    r"127\.0\.0\.1",
    r"localhost",
]

REDIRECT_PATTERNS = [
    r"Location:.*?http",
    r"location\.href",
    r"window\.location",
    r"document\.location",
    r"meta.*?http-equiv.*?refresh",
    r"redirect",
    r"302",
    r"301",
]

OPEN_REDIRECT_PATTERNS = [
    r"evil\.com",
    r"attacker\.com",
    r"malicious",
    r"redirect.*?url",
    r"return.*?url",
    r"next.*?url",
    r"continue.*?url",
    r"go.*?url",
    r"dest.*?url",
    r"target.*?url",
    r"callback.*?url",
    r"redir.*?url",
]


class SSRFRedirectScanner:
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
            logger.error(f"SSRF/Redirect baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "ssrf_internal")
            payload_str = payload.get("payload_string", "")

            if subtype == "ssrf_internal":
                result = await self._test_ssrf_internal(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "ssrf_cloud":
                result = await self._test_ssrf_cloud(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "ssrf_dns_rebind":
                result = await self._test_ssrf_dns_rebind(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "ssrf_file":
                result = await self._test_ssrf_file(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "open_redirect":
                result = await self._test_open_redirect(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_ssrf_internal(
                    url, method, param_name, payload_str, baseline
                )

            if result:
                findings.append(result)

        self._findings = findings
        return findings

    async def _get_baseline(self, url: str, method: str, param_name: str) -> dict:
        start = time.time()
        async with httpx.AsyncClient(
            verify=self.verify_ssl, timeout=self.timeout, follow_redirects=False
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
        self, url: str, method: str, param_name: str, payload: str, follow_redirects: bool = False
    ) -> dict:
        start = time.time()
        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout, follow_redirects=follow_redirects
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

    async def _test_ssrf_internal(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            if "timeout" in resp.get("error", "").lower():
                return self._create_finding(
                    title="SSRF - Internal Network",
                    description="SSRF to internal network detected. Request timed out accessing internal resource.",
                    severity="high",
                    cvss=8.6,
                    confidence="medium",
                    family="ssrf_redirect",
                    subtype="ssrf_internal",
                    payload=payload,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                    response_data={"response_time": resp["response_time"]},
                    evidence={"timeout": True, "internal_access": True},
                )
            return None

        body = resp["body"]
        time_diff = resp["response_time"] - baseline["response_time"]
        body_diff = abs(resp["body_length"] - baseline["body_length"])

        has_internal = any(ip in payload.lower() for ip in ["127.0.0.1", "localhost", "10.", "172.16", "192.168", "[::1]"])

        if has_internal and (time_diff > 2.0 or body_diff > 100):
            return self._create_finding(
                title="SSRF - Internal Network",
                description=f"SSRF to internal network detected. Internal IP in payload caused response anomaly.",
                severity="high",
                cvss=8.6,
                confidence="medium",
                family="ssrf_redirect",
                subtype="ssrf_internal",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "response_time": resp["response_time"]},
                evidence={"time_diff": time_diff, "body_diff": body_diff},
            )

        if has_internal and resp["status_code"] in (200, 301, 302) and baseline["status_code"] in (200, 301, 302):
            if resp["body_length"] > baseline["body_length"] * 1.2:
                return self._create_finding(
                    title="SSRF - Internal Network",
                    description="SSRF to internal network. Response body changed significantly with internal IP payload.",
                    severity="high",
                    cvss=8.6,
                    confidence="medium",
                    family="ssrf_redirect",
                    subtype="ssrf_internal",
                    payload=payload,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                    response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                    evidence={"body_length_change": True},
                )
        return None

    async def _test_ssrf_cloud(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, CLOUD_METADATA_PATTERNS)

        if matches:
            return self._create_finding(
                title="SSRF - Cloud Metadata",
                description=f"SSRF cloud metadata access detected. Patterns: {', '.join(matches[:3])}",
                severity="critical",
                cvss=10.0,
                confidence="high",
                family="ssrf_redirect",
                subtype="ssrf_cloud",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"cloud_patterns": matches[:5], "metadata_accessed": True},
            )
        return None

    async def _test_ssrf_dns_rebind(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, SSRF_DNS_REBIND_PATTERNS)

        if matches or ("rebind" in payload.lower() and resp["status_code"] != baseline["status_code"]):
            return self._create_finding(
                title="SSRF - DNS Rebinding",
                description="Potential DNS rebinding attack detected.",
                severity="high",
                cvss=7.5,
                confidence="low",
                family="ssrf_redirect",
                subtype="ssrf_dns_rebind",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"dns_rebind_attempt": True},
            )
        return None

    async def _test_ssrf_file(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, SSRF_FILE_PATTERNS)

        if matches:
            return self._create_finding(
                title="SSRF - File Protocol",
                description=f"SSRF via file:// protocol detected. File content leaked: {', '.join(matches[:3])}",
                severity="critical",
                cvss=9.8,
                confidence="high",
                family="ssrf_redirect",
                subtype="ssrf_file",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"file_patterns": matches[:5]},
            )
        return None

    async def _test_open_redirect(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload, follow_redirects=False)
        if resp.get("error"):
            return None

        body = resp["body"]
        headers = resp["headers"]
        location = headers.get("location", headers.get("Location", ""))

        is_redirect = resp["status_code"] in (301, 302, 303, 307, 308)

        if is_redirect and payload.lower() in location.lower():
            return self._create_finding(
                title="Open Redirect",
                description=f"Open redirect detected. User redirected to attacker-controlled URL: {location[:200]}",
                severity="medium",
                cvss=6.1,
                confidence="high",
                family="ssrf_redirect",
                subtype="open_redirect",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "redirect_location": location[:500]},
                evidence={"redirect_to": location, "payload_in_location": True},
            )

        body_matches = self._match_patterns(body, OPEN_REDIRECT_PATTERNS)
        if body_matches and any(p.lower() in body.lower() for p in ["evil.com", "attacker.com", "malicious"]):
            return self._create_finding(
                title="Open Redirect",
                description="Open redirect detected. Attacker URL reflected in response body.",
                severity="medium",
                cvss=6.1,
                confidence="medium",
                family="ssrf_redirect",
                subtype="open_redirect",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"body_matches": body_matches[:3]},
            )
        return None
