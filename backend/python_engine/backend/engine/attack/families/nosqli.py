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

NOSQL_OPERATOR_PAYLOADS = {
    "$gt": {"$gt": ""},
    "$ne": {"$ne": ""},
    "$regex": {"$regex": ".*"},
    "$lt": {"$lt": "z"},
    "$gte": {"$gte": ""},
    "$lte": {"$lte": "zzzzz"},
    "$exists": {"$exists": True},
    "$nin": {"$nin": []},
    "$not": {"$not": {"$regex": "^$"}},
    "$where": {"$where": "this"},
    "$expr": {"$expr": {"$gt": ["$field", ""]}},
}

JSON_INJECTION_PATTERNS = [
    r"__proto__",
    r"constructor",
    r"toString",
    r"valueOf",
    r"prototype",
    r"Object\.assign",
]

GRAPHQL_ERROR_PATTERNS = [
    r"Syntax Error",
    r"Cannot query field",
    r"Field .*? is not defined",
    r"Unknown argument",
    r"Variable .*? is not defined",
    r"Category .*? not found",
]


class NoSQLiScanner:
    def __init__(self, timeout: int = 30, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._findings = []

    async def scan(self, element: dict, payloads: list[dict]) -> list[dict]:
        findings = []
        url = element.get("url", "")
        param_name = element.get("parameter_name", "")
        method = element.get("http_method", "GET").upper()
        content_type = element.get("content_type", "json")
        scan_id = element.get("scan_id", "")

        if not url or not param_name:
            return findings

        try:
            baseline = await self._get_baseline(url, method, param_name, content_type)
        except Exception as e:
            logger.error(f"NoSQLi baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "operator_injection")
            payload_str = payload.get("payload_string", "")

            if subtype == "operator_injection":
                result = await self._test_operator_injection(
                    url, method, param_name, payload_str, baseline, content_type
                )
            elif subtype == "json_injection":
                result = await self._test_json_injection(
                    url, method, param_name, payload_str, baseline, content_type
                )
            elif subtype == "graphql_nosql":
                result = await self._test_graphql_nosql(
                    url, method, param_name, payload_str, baseline
                )
            else:
                result = await self._test_operator_injection(
                    url, method, param_name, payload_str, baseline, content_type
                )

            if result:
                findings.append(result)

        self._findings = findings
        return findings

    async def _get_baseline(
        self, url: str, method: str, param_name: str, content_type: str
    ) -> dict:
        start = time.time()
        async with httpx.AsyncClient(
            verify=self.verify_ssl, timeout=self.timeout, follow_redirects=True
        ) as client:
            headers = {"Content-Type": f"application/{content_type}"} if content_type == "json" else {}
            if method == "GET":
                resp = await client.get(url, headers=headers)
            else:
                data = {param_name: "baseline_test_value"}
                resp = await client.post(url, json=data, headers=headers)
            elapsed = time.time() - start
            return {
                "status_code": resp.status_code,
                "body": resp.text,
                "body_length": len(resp.text),
                "response_time": elapsed,
                "headers": dict(resp.headers),
            }

    async def _send_payload_json(
        self, url: str, method: str, param_name: str, payload: dict
    ) -> dict:
        start = time.time()
        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout, follow_redirects=True
            ) as client:
                headers = {"Content-Type": "application/json"}
                if method == "GET":
                    inject_url = f"{url}?{param_name}={json.dumps(payload)}"
                    resp = await client.get(inject_url, headers=headers)
                else:
                    resp = await client.post(url, json={param_name: payload}, headers=headers)
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

    async def _send_payload_string(
        self, url: str, method: str, param_name: str, payload_str: str
    ) -> dict:
        start = time.time()
        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout, follow_redirects=True
            ) as client:
                if method == "GET":
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = [payload_str]
                    new_query = urlencode(params, doseq=True)
                    inject_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment,
                    ))
                    resp = await client.get(inject_url)
                else:
                    resp = await client.post(url, data={param_name: payload_str})
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

    def _check_response_anomaly(self, resp: dict, baseline: dict) -> list[str]:
        anomalies = []
        if resp["status_code"] != baseline["status_code"]:
            anomalies.append("status_code_change")
        if baseline["body_length"] > 0:
            length_diff = abs(resp["body_length"] - baseline["body_length"]) / baseline["body_length"]
            if length_diff > 0.20:
                anomalies.append("body_length_change")
        if baseline["response_time"] > 0 and resp["response_time"] > 0:
            time_ratio = resp["response_time"] / baseline["response_time"]
            if time_ratio > 3.0:
                anomalies.append("response_time_spike")
        if "error" in resp.get("body", "").lower():
            if "error" not in baseline.get("body", "").lower():
                anomalies.append("error_disclosure")
        return anomalies

    async def _test_operator_injection(
        self, url: str, method: str, param_name: str, payload_str: str,
        baseline: dict, content_type: str
    ) -> Optional[dict]:
        try:
            nosql_payload = json.loads(payload_str)
        except (json.JSONDecodeError, TypeError):
            nosql_payload = {"$gt": ""}

        resp = await self._send_payload_json(url, method, param_name, nosql_payload)
        if resp.get("error"):
            return None

        anomalies = self._check_response_anomaly(resp, baseline)

        if anomalies:
            high_priv = resp["status_code"] == 200 and baseline["status_code"] in (401, 403)
            return self._create_finding(
                title="NoSQL Injection - Operator Injection",
                description=f"NosQL operator injection detected. Payload manipulated query operators: {json.dumps(nosql_payload)[:200]}",
                severity="critical" if high_priv else "high",
                cvss=9.8 if high_priv else 8.6,
                confidence="high" if high_priv else "medium",
                family="nosql",
                subtype="operator_injection",
                payload=json.dumps(nosql_payload),
                request_data={"url": url, "method": method, "param": param_name, "payload": nosql_payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"anomalies": anomalies, "baseline_status": baseline["status_code"]},
            )

        body_lower = resp["body"].lower()
        if any(op in body_lower for op in ["$gt", "$ne", "$regex", "$where", "$exists"]):
            return self._create_finding(
                title="NoSQL Injection - Operator Reflected",
                description="NoSQL operator payload reflected in response, suggesting injection point.",
                severity="high",
                cvss=7.5,
                confidence="medium",
                family="nosql",
                subtype="operator_injection",
                payload=json.dumps(nosql_payload),
                request_data={"url": url, "method": method, "param": param_name, "payload": nosql_payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"body_reflection": True},
            )
        return None

    async def _test_json_injection(
        self, url: str, method: str, param_name: str, payload_str: str,
        baseline: dict, content_type: str
    ) -> Optional[dict]:
        resp = await self._send_payload_string(url, method, param_name, payload_str)
        if resp.get("error"):
            return None

        body = resp["body"]
        anomalies = self._check_response_anomaly(resp, baseline)

        json_errors = [
            "json", "parse", "syntax", "invalid", "unexpected",
            "malformed", "decode",
        ]
        error_count = sum(1 for err in json_errors if err in body.lower())

        if anomalies or error_count >= 2:
            return self._create_finding(
                title="NoSQL Injection - JSON Injection",
                description="JSON injection detected. Malformed JSON payload caused server-side parsing anomaly.",
                severity="high",
                cvss=8.6,
                confidence="medium" if anomalies else "low",
                family="nosql",
                subtype="json_injection",
                payload=payload_str,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload_str},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"anomalies": anomalies, "json_errors_found": error_count},
            )

        for pattern in JSON_INJECTION_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return self._create_finding(
                    title="NoSQL Injection - JSON Prototype Pollution",
                    description=f"JSON prototype pollution attempt detected. Pattern: {pattern}",
                    severity="high",
                    cvss=8.1,
                    confidence="medium",
                    family="nosql",
                    subtype="json_injection",
                    payload=payload_str,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload_str},
                    response_data={"status_code": resp["status_code"]},
                    evidence={"matched_pattern": pattern},
                )
        return None

    async def _test_graphql_nosql(
        self, url: str, method: str, param_name: str, payload_str: str, baseline: dict
    ) -> Optional[dict]:
        try:
            gql_payload = json.loads(payload_str)
        except (json.JSONDecodeError, TypeError):
            gql_payload = {"query": payload_str}

        resp = await self._send_payload_json(url, "POST", param_name, gql_payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        for pattern in GRAPHQL_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return self._create_finding(
                    title="NoSQL Injection - GraphQL/NoSQL",
                    description=f"GraphQL error disclosed, indicating potential NoSQL injection surface: {pattern}",
                    severity="high",
                    cvss=7.5,
                    confidence="medium",
                    family="nosql",
                    subtype="graphql_nosql",
                    payload=json.dumps(gql_payload),
                    request_data={"url": url, "method": "POST", "param": param_name, "payload": gql_payload},
                    response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                    evidence={"matched_pattern": pattern},
                )

        anomalies = self._check_response_anomaly(resp, baseline)
        if anomalies:
            return self._create_finding(
                title="NoSQL Injection - GraphQL Anomaly",
                description="GraphQL NoSQL injection attempt caused response anomaly.",
                severity="high",
                cvss=7.5,
                confidence="low",
                family="nosql",
                subtype="graphql_nosql",
                payload=json.dumps(gql_payload),
                request_data={"url": url, "method": "POST", "param": param_name, "payload": gql_payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"anomalies": anomalies},
            )
        return None
