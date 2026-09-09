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

MASS_ASSIGNMENT_PATTERNS = [
    r"admin.*?true",
    r"role.*?admin",
    r"privilege.*?elevated",
    r"is_admin.*?true",
    r"confirmed.*?true",
    r"verified.*?true",
    r"approved.*?true",
    r"superuser.*?true",
    r"staff.*?true",
    r"internal.*?true",
    r"debug.*?true",
    r"test.*?true",
    r"bypass.*?true",
]

HPP_PATTERNS = [
    r"admin",
    r"role.*?admin",
    r"privilege",
    r"elevated",
    r"bypass",
    r"override",
    r"priority",
    r"multiple.*?values",
    r"duplicate.*?param",
]

SSPP_PATTERNS = [
    r"admin",
    r"role.*?admin",
    r"bypass",
    r"override",
    r"secondary",
    r"fallback",
    r"default.*?overridden",
    r"conflict",
]

WILDCARD_PATTERNS = [
    r"\*",
    r"\[.*?\]",
    r"\{.*?\}",
    r"all",
    r"every",
    r"full",
    r"complete",
    r"global",
    r"admin.*?\*",
    r"role.*?\*",
]


class ParameterPollutionScanner:
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
            logger.error(f"Parameter pollution baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "mass_assignment")
            payload_str = payload.get("payload_string", "")

            if subtype == "mass_assignment":
                result = await self._test_mass_assignment(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "hpp":
                result = await self._test_hpp(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "sspp":
                result = await self._test_sspp(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "wildcard":
                result = await self._test_wildcard(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_mass_assignment(
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

    async def _send_mass_assignment(
        self, url: str, method: str, base_params: dict, extra_params: dict
    ) -> dict:
        start = time.time()
        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout, follow_redirects=True
            ) as client:
                all_params = {**base_params, **extra_params}
                if method == "GET":
                    parsed = urlparse(url)
                    query_parts = []
                    for k, v in all_params.items():
                        query_parts.append(f"{k}={v}")
                    inject_url = f"{url}?{'&'.join(query_parts)}"
                    resp = await client.get(inject_url)
                else:
                    resp = await client.post(url, data=all_params)
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

    async def _send_duplicate_param(
        self, url: str, method: str, param_name: str, value1: str, value2: str
    ) -> dict:
        start = time.time()
        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout, follow_redirects=True
            ) as client:
                if method == "GET":
                    parsed = urlparse(url)
                    new_query = f"{parsed.query}&{param_name}={value2}" if parsed.query else f"{param_name}={value2}"
                    inject_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment,
                    ))
                    resp = await client.get(inject_url)
                else:
                    content = f"{param_name}={value1}&{param_name}={value2}"
                    resp = await client.post(
                        url,
                        content=content,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
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

    async def _test_mass_assignment(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        try:
            extra = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            extra = {"admin": "true", "role": "admin"}

        resp = await self._send_mass_assignment(url, method, {param_name: "test"}, extra)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, MASS_ASSIGNMENT_PATTERNS)

        if matches:
            return self._create_finding(
                title="Parameter Pollution - Mass Assignment",
                description=f"Mass assignment vulnerability detected. Extra parameters accepted: {', '.join(matches[:3])}",
                severity="critical",
                cvss=9.1,
                confidence="high",
                family="parameter_pollution",
                subtype="mass_assignment",
                payload=json.dumps(extra),
                request_data={"url": url, "method": method, "extra_params": extra},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:5], "extra_params_accepted": True},
            )

        if resp["status_code"] == 200 and baseline["status_code"] in (200, 302):
            if resp["body_length"] > baseline["body_length"] * 1.2:
                return self._create_finding(
                    title="Parameter Pollution - Mass Assignment (Anomaly)",
                    description="Extra parameters caused significant response change.",
                    severity="high",
                    cvss=8.1,
                    confidence="medium",
                    family="parameter_pollution",
                    subtype="mass_assignment",
                    payload=json.dumps(extra),
                    request_data={"url": url, "method": method, "extra_params": extra},
                    response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                    evidence={"body_length_change": True},
                )
        return None

    async def _test_hpp(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_duplicate_param(url, method, param_name, "test", payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, HPP_PATTERNS)

        if matches:
            return self._create_finding(
                title="Parameter Pollution - HPP",
                description=f"HTTP Parameter Pollution detected. Duplicate parameter accepted different values.",
                severity="high",
                cvss=7.5,
                confidence="high",
                family="parameter_pollution",
                subtype="hpp",
                payload=f"{param_name}=test&{param_name}={payload}",
                request_data={"url": url, "method": method, "param": param_name, "duplicate_value": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"hpp_patterns": matches[:5]},
            )

        if resp["status_code"] != baseline["status_code"]:
            return self._create_finding(
                title="Parameter Pollution - HPP (Anomaly)",
                description="Duplicate parameter caused status code change.",
                severity="medium",
                cvss=6.1,
                confidence="medium",
                family="parameter_pollution",
                subtype="hpp",
                payload=f"{param_name}=test&{param_name}={payload}",
                request_data={"url": url, "method": method, "param": param_name, "duplicate_value": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"status_change": True},
            )

        body_len_diff = abs(resp["body_length"] - baseline["body_length"])
        if body_len_diff > 50:
            return self._create_finding(
                title="Parameter Pollution - HPP (Length Change)",
                description=f"HPP caused response body length change of {body_len_diff} bytes.",
                severity="medium",
                cvss=6.1,
                confidence="low",
                family="parameter_pollution",
                subtype="hpp",
                payload=f"{param_name}=test&{param_name}={payload}",
                request_data={"url": url, "method": method, "param": param_name, "duplicate_value": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"body_length_diff": body_len_diff},
            )
        return None

    async def _test_sspp(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, SSPP_PATTERNS)

        if matches:
            return self._create_finding(
                title="Parameter Pollution - SSPP",
                description=f"Server-Side Parameter Pollution detected: {', '.join(matches[:3])}",
                severity="high",
                cvss=8.1,
                confidence="high",
                family="parameter_pollution",
                subtype="sspp",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"sspp_patterns": matches[:5]},
            )

        if resp["status_code"] != baseline["status_code"] and resp["status_code"] in (200, 500):
            return self._create_finding(
                title="Parameter Pollution - SSPP (Anomaly)",
                description="SSPP payload caused unexpected status code.",
                severity="medium",
                cvss=6.5,
                confidence="medium",
                family="parameter_pollution",
                subtype="sspp",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"anomaly": True},
            )
        return None

    async def _test_wildcard(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        matches = self._match_patterns(body, WILDCARD_PATTERNS)

        if matches:
            return self._create_finding(
                title="Parameter Pollution - Wildcard",
                description=f"Wildcard parameter pollution detected: {', '.join(matches[:3])}",
                severity="medium",
                cvss=6.1,
                confidence="medium",
                family="parameter_pollution",
                subtype="wildcard",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"wildcard_patterns": matches[:3]},
            )

        if payload in body and ("*" in payload or "[" in payload):
            return self._create_finding(
                title="Parameter Pollution - Wildcard (Reflected)",
                description="Wildcard payload reflected in response body.",
                severity="low",
                cvss=3.7,
                confidence="low",
                family="parameter_pollution",
                subtype="wildcard",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"payload_reflected": True},
            )
        return None
