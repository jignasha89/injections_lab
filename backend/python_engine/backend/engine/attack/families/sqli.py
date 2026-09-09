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

SQL_ERROR_PATTERNS = {
    "mysql": [
        r"sql syntax.*?mysql",
        r"mysql_fetch",
        r"valid mysql result",
        r"supplied argument is not a valid mysql",
        r"warning.*?mysql_",
        r"myodbc",
        r"com\.mysql\.jdbc",
        r"unclosed quotation mark after the character string",
        r"mysql_num_rows",
        r"mysql_affected_rows",
    ],
    "postgresql": [
        r"pg_query",
        r"pg_exec",
        r"postgresql",
        r"syntax error at or near",
        r"unterminated quoted string at or near",
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"org\.postgresql\.util\.psql",
        r"relation .* does not exist",
    ],
    "mssql": [
        r"microsoft odbc",
        r"microsoft ole db provider for odbc",
        r"unclosed quotation mark after the character string",
        r"mssql_query",
        r"mssql_fetch",
        r"odbc sql server driver",
        r"microsoft sql server",
        r"incorrect syntax near",
        r"unterminated string constant",
        r"conversion failed when",
    ],
    "oracle": [
        r"ora-\d{5}",
        r"oracle\.jdbc",
        r"oracle\.sql",
        r"quoted string not properly terminated",
        r"oracle error",
        r"ora-01756",
        r"ora-00933",
        r"ora-00921",
    ],
    "sqlite": [
        r"sqlite3",
        r"sqlite\.SQLException",
        r"unrecognized token:",
        r"near .*: syntax error",
        r"no such table",
        r"sqlce",
        r"system\.data\.sqlite",
    ],
    "generic": [
        r"you have an error in your sql syntax",
        r"sql syntax",
        r"database error",
        r"query failed",
        r"sql command denied",
        r"sql_exception",
        r"sql.*?exception",
        r"odbc.*?driver",
        r"unexpected end of sql command",
        r"unterminated string",
        r"quoted string not properly terminated",
        r"unclosed quotation mark",
    ],
}

AUTH_BYPASS_PATTERNS = [
    r"welcome.*?admin",
    r"dashboard",
    r"logout",
    r"admin.*?panel",
    r"successful.*?login",
    r"session.*?id",
    r"account.*?access",
]

UNION_ERROR_PATTERNS = [
    r"column.*?of.*?table.*?is not equal",
    r"select.*?list.*?is not in.*?group by",
    r"union.*?distinct.*?select",
    r"different number of columns",
    r"all.*?select.*?must.*?have.*?same.*?number",
]

BLIND_TRUE_BODY_RATIO = 0.85
BLIND_FALSE_BODY_RATIO = 1.15


class SQLiScanner:
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
            logger.error(f"SQLi baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "error-based")
            payload_str = payload.get("payload_string", "")

            if subtype == "auth_bypass":
                result = await self._test_auth_bypass(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "error_based":
                result = await self._test_error_based(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "boolean_blind":
                result = await self._test_boolean_blind(
                    url, method, param_name, payload_str, baseline, payloads
                )
            elif subtype == "time_blind":
                result = await self._test_time_blind(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "union":
                result = await self._test_union(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "out_of_band":
                result = await self._test_oob(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype == "stored":
                result = await self._test_stored(
                    url, method, param_name, payload_str, baseline
                )
            elif subtype in ("dbms_specific", "mysql", "postgresql", "mssql", "oracle", "sqlite"):
                result = await self._test_dbms_specific(
                    url, method, param_name, payload_str, baseline, subtype
                )
            else:
                result = await self._test_error_based(
                    url, method, param_name, payload_str, baseline
                )

            if result:
                findings.append(result)

        self._findings = findings
        return findings

    async def _get_baseline(
        self, url: str, method: str, param_name: str
    ) -> dict:
        start = time.time()
        async with httpx.AsyncClient(
            verify=self.verify_ssl, timeout=self.timeout, follow_redirects=True
        ) as client:
            if method == "GET":
                resp = await client.get(url)
            else:
                resp = await client.post(url, data={param_name: "baseline_test_value"})
            elapsed = time.time() - start
            return {
                "status_code": resp.status_code,
                "body": resp.text,
                "body_length": len(resp.text),
                "response_time": elapsed,
                "headers": dict(resp.headers),
            }

    def _build_url(
        self, url: str, method: str, param_name: str, payload: str
    ) -> tuple:
        parsed = urlparse(url)
        if method == "GET":
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment,
            ))
            return new_url, None
        else:
            return url, {param_name: payload}

    async def _send_payload(
        self, url: str, method: str, param_name: str, payload: str
    ) -> dict:
        start = time.time()
        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl, timeout=self.timeout, follow_redirects=True
            ) as client:
                inject_url, post_data = self._build_url(url, method, param_name, payload)
                if method == "GET":
                    resp = await client.get(inject_url)
                else:
                    resp = await client.post(inject_url, data=post_data)
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

    def _match_error_patterns(self, body: str, dbms: str = "generic") -> list[str]:
        matches = []
        body_lower = body.lower()
        patterns = SQL_ERROR_PATTERNS.get(dbms, []) + SQL_ERROR_PATTERNS["generic"]
        for pattern in patterns:
            if re.search(pattern, body_lower, re.IGNORECASE):
                matches.append(pattern)
        return matches

    def _detect_dbms(self, body: str) -> str:
        body_lower = body.lower()
        for dbms in ["mysql", "postgresql", "mssql", "oracle", "sqlite"]:
            if any(re.search(p, body_lower, re.IGNORECASE) for p in SQL_ERROR_PATTERNS.get(dbms, [])):
                return dbms
        return "generic"

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

    async def _test_auth_bypass(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        body_lower = body.lower()

        for pattern in AUTH_BYPASS_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                if resp["status_code"] != baseline["status_code"] or len(body) != baseline["body_length"]:
                    return self._create_finding(
                        title="SQL Injection - Authentication Bypass",
                        description=f"SQL authentication bypass detected. The payload bypassed authentication controls.",
                        severity="critical",
                        cvss=9.8,
                        confidence="high",
                        family="sqli",
                        subtype="auth_bypass",
                        payload=payload,
                        request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                        response_data={"status_code": resp["status_code"], "body_length": resp["body_length"], "response_time": resp["response_time"]},
                        evidence={"matched_pattern": pattern, "baseline_status": baseline["status_code"], "response_status": resp["status_code"]},
                    )

        if resp["status_code"] in (200, 302, 301) and any(
            rp in body_lower for rp in AUTH_BYPASS_PATTERNS
        ):
            dbms = self._detect_dbms(body)
            if dbms != "generic":
                return self._create_finding(
                    title="SQL Injection - Authentication Bypass",
                    description=f"SQL authentication bypass via {dbms}-specific injection.",
                    severity="critical",
                    cvss=9.8,
                    confidence="medium",
                    family="sqli",
                    subtype="auth_bypass",
                    payload=payload,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                    response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                    evidence={"detected_dbms": dbms},
                )
        return None

    async def _test_error_based(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        dbms = self._detect_dbms(body)
        error_matches = self._match_error_patterns(body, dbms)

        if error_matches:
            return self._create_finding(
                title="SQL Injection - Error-Based",
                description=f"Error-based SQL injection detected. DBMS: {dbms}. Errors leaked in response indicate unsanitized input.",
                severity="critical",
                cvss=9.8,
                confidence="high",
                family="sqli",
                subtype="error_based",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"], "response_time": resp["response_time"]},
                evidence={"detected_dbms": dbms, "error_patterns_matched": error_matches[:5], "baseline_status": baseline["status_code"]},
            )

        if resp["status_code"] == 500 and baseline["status_code"] != 500:
            return self._create_finding(
                title="SQL Injection - Error-Based (500 Error)",
                description="Server returned 500 error with payload, suggesting SQL syntax error.",
                severity="high",
                cvss=8.6,
                confidence="medium",
                family="sqli",
                subtype="error_based",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"status_change": f"{baseline['status_code']} -> {resp['status_code']}"},
            )
        return None

    async def _test_boolean_blind(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict, all_payloads: list
    ) -> Optional[dict]:
        true_payload = payload
        false_payload = true_payload.replace("1=1", "1=2").replace("true", "false")

        if true_payload == false_payload:
            for p in all_payloads:
                if p.get("subtype") == "boolean_blind" and "1=2" in p.get("payload_string", ""):
                    false_payload = p["payload_string"]
                    break

        resp_true = await self._send_payload(url, method, param_name, true_payload)
        resp_false = await self._send_payload(url, method, param_name, false_payload)

        if resp_true.get("error") or resp_false.get("error"):
            return None

        true_len = resp_true["body_length"]
        false_len = resp_false["body_length"]
        baseline_len = baseline["body_length"]

        true_diff = abs(true_len - baseline_len) / max(baseline_len, 1)
        false_diff = abs(false_len - baseline_len) / max(baseline_len, 1)

        if true_diff < 0.05 and false_diff > 0.15:
            return self._create_finding(
                title="SQL Injection - Boolean-Based Blind",
                description="Boolean-based blind SQL injection detected. True/false conditions produce different responses.",
                severity="critical",
                cvss=9.1,
                confidence="high",
                family="sqli",
                subtype="boolean_blind",
                payload=f"{true_payload} (true) / {false_payload} (false)",
                request_data={"url": url, "method": method, "param": param_name, "true_payload": true_payload, "false_payload": false_payload},
                response_data={"true_response_length": true_len, "false_response_length": false_len, "baseline_length": baseline_len},
                evidence={"true_body_diff": true_diff, "false_body_diff": false_diff},
            )
        return None

    async def _test_time_blind(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        baseline_time = baseline["response_time"]
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            if "timeout" in resp.get("error", "").lower():
                return self._create_finding(
                    title="SQL Injection - Time-Based Blind",
                    description="Time-based blind SQL injection detected. Payload caused request timeout/delay.",
                    severity="critical",
                    cvss=9.1,
                    confidence="high",
                    family="sqli",
                    subtype="time_blind",
                    payload=payload,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                    response_data={"response_time": resp["response_time"], "baseline_time": baseline_time},
                    evidence={"time_ratio": resp["response_time"] / max(baseline_time, 0.001)},
                )
            return None

        response_time = resp["response_time"]
        time_ratio = response_time / max(baseline_time, 0.001)

        if time_ratio > 3.0 and response_time - baseline_time > 2.0:
            return self._create_finding(
                title="SQL Injection - Time-Based Blind",
                description=f"Time-based blind SQL injection detected. Response time was {time_ratio:.1f}x slower than baseline.",
                severity="critical",
                cvss=9.1,
                confidence="high",
                family="sqli",
                subtype="time_blind",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"response_time": response_time, "baseline_time": baseline_time},
                evidence={"time_ratio": time_ratio, "time_delta": response_time - baseline_time},
            )
        return None

    async def _test_union(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]

        for pattern in UNION_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return self._create_finding(
                    title="SQL Injection - UNION-Based",
                    description=f"UNION-based SQL injection detected. Column mismatch error leaked: {pattern}",
                    severity="critical",
                    cvss=9.8,
                    confidence="high",
                    family="sqli",
                    subtype="union",
                    payload=payload,
                    request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                    response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                    evidence={"error_pattern": pattern},
                )

        error_matches = self._match_error_patterns(body)
        if error_matches and "union" in payload.lower():
            return self._create_finding(
                title="SQL Injection - UNION-Based",
                description="UNION SQL injection attempt triggered SQL error, indicating query structure manipulation.",
                severity="critical",
                cvss=9.5,
                confidence="medium",
                family="sqli",
                subtype="union",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"error_patterns": error_matches[:3]},
            )
        return None

    async def _test_oob(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        dbms = self._detect_dbms(body)

        if dbms != "generic":
            return self._create_finding(
                title="SQL Injection - Out-of-Band",
                description=f"Out-of-band SQL injection attempt with {dbms}-specific payload.",
                severity="critical",
                cvss=9.8,
                confidence="medium",
                family="sqli",
                subtype="out_of_band",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"detected_dbms": dbms},
            )

        if resp["status_code"] != baseline["status_code"]:
            return self._create_finding(
                title="SQL Injection - Out-of-Band",
                description="Out-of-band SQL injection payload caused status code change.",
                severity="high",
                cvss=8.5,
                confidence="medium",
                family="sqli",
                subtype="out_of_band",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "baseline_status": baseline["status_code"]},
                evidence={"status_change": f"{baseline['status_code']} -> {resp['status_code']}"},
            )
        return None

    async def _test_stored(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        error_matches = self._match_error_patterns(body)

        if error_matches:
            return self._create_finding(
                title="SQL Injection - Stored",
                description="Stored SQL injection detected. Payload triggered error on storage/retrieval.",
                severity="critical",
                cvss=9.8,
                confidence="medium",
                family="sqli",
                subtype="stored",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"error_patterns": error_matches[:3]},
            )
        return None

    async def _test_dbms_specific(
        self, url: str, method: str, param_name: str, payload: str, baseline: dict, subtype: str
    ) -> Optional[dict]:
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None

        body = resp["body"]
        body_lower = body.lower()
        dbms_key = subtype if subtype in SQL_ERROR_PATTERNS else "generic"
        patterns = SQL_ERROR_PATTERNS.get(dbms_key, []) + SQL_ERROR_PATTERNS["generic"]

        matches = [p for p in patterns if re.search(p, body_lower, re.IGNORECASE)]
        if matches:
            return self._create_finding(
                title=f"SQL Injection - {dbms_key.upper()} Specific",
                description=f"{dbms_key.upper()}-specific SQL injection detected. DBMS fingerprinted via error response.",
                severity="critical",
                cvss=9.8,
                confidence="high",
                family="sqli",
                subtype=dbms_key,
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"detected_dbms": dbms_key, "matched_patterns": matches[:3]},
            )
        return None
