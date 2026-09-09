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

PROMPT_INJECTION_PATTERNS = [
    r"ignore.*?previous.*?instructions",
    r"ignore.*?above",
    r"ignore.*?all.*?prior",
    r"disregard.*?instructions",
    r"forget.*?everything",
    r"new.*?instructions",
    r"override.*?instructions",
    r"act.*?as.*?if",
    r"pretend.*?you.*?are",
    r"you.*?are.*?now",
    r"system.*?prompt",
    r"<\|system\|>",
    r"<\|user\|>",
    r"<\|assistant\|>",
    r"###.*?system",
    r"###.*?human",
    r"###.*?assistant",
    r"ADMIN:",
    r"INSTRUCTION:",
    r"SYSTEM:",
    r"\[INST\]",
    r"\[/INST\]",
]

DIRECT_PROMPT_PATTERNS = [
    r"bypass.*?safety",
    r"jailbreak",
    r"DAN.*?mode",
    r"do.*?anything.*?now",
    r"unrestricted.*?mode",
    r"developer.*?mode",
    r"debug.*?mode",
    r"maintenance.*?mode",
    r"test.*?mode",
]

INDIRECT_PROMPT_PATTERNS = [
    r"<img.*?onerror.*?prompt",
    r"<script.*?prompt",
    r"javascript.*?prompt",
    r"data:.*?text/html.*?prompt",
    r"<svg.*?prompt",
    r"onload.*?prompt",
    r"onerror.*?prompt",
]

RAG_INJECTION_PATTERNS = [
    r"system.*?message",
    r"assistant.*?message",
    r"human.*?message",
    r"###.*?System",
    r"###.*?Assistant",
    r"###.*?Human",
    r"END.*?OF.*?TEXT",
    r"EOS.*?TOKEN",
]

PROTOTYPE_POLLUTION_PATTERNS = [
    r"__proto__",
    r"constructor\[",
    r"constructor\.prototype",
    r"__defineGetter__",
    r"__defineSetter__",
    r"toString\s*=\s*function",
    r"valueOf\s*=\s*function",
    r"isPrototypeOf",
]

OAUTH_INJECTION_PATTERNS = [
    r"redirect_uri.*?evil",
    r"client_id.*?stolen",
    r"code.*?intercepted",
    r"access_token.*?leaked",
    r"state.*?bypassed",
    r"nonce.*?replay",
    r"pkce.*?bypass",
    r"token.*?forged",
    r"jwt.*?none",
    r"alg.*?none",
    r"RS256.*?HS256",
    r"key.*?confusion",
]

GRAPHQL_INTROSPECTION_PATTERNS = [
    r"__schema",
    r"__type",
    r"queryType",
    r"mutationType",
    r"subscriptionType",
    r"types.*?name",
    r"fields.*?name",
    r"enumValues",
    r"inputFields",
    r"possibleTypes",
    r"introspection",
    r"Schema Introspection",
    r"GraphQL",
]

DEPENDENCY_CONFUSION_PATTERNS = [
    r"package.*?not.*?found",
    r"404.*?Not Found",
    r"npm.*?ERR",
    r"pip.*?error",
    r"private.*?registry",
    r"authentication.*?required",
    r"authorization.*?denied",
    r"401.*?Unauthorized",
    r"403.*?Forbidden",
]


class ModernInjectionScanner:
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
            logger.error(f"Modern injection baseline failed for {url}: {e}")
            return findings

        for payload in payloads:
            subtype = payload.get("subtype", "direct_prompt")
            payload_str = payload.get("payload_string", "")

            if subtype == "direct_prompt":
                result = await self._test_direct_prompt(url, method, param_name, payload_str, baseline)
            elif subtype == "indirect_prompt":
                result = await self._test_indirect_prompt(url, method, param_name, payload_str, baseline)
            elif subtype == "rag_prompt":
                result = await self._test_rag_prompt(url, method, param_name, payload_str, baseline)
            elif subtype == "prototype_pollution":
                result = await self._test_prototype_pollution(url, method, param_name, payload_str, baseline)
            elif subtype == "oauth_injection":
                result = await self._test_oauth_injection(url, method, param_name, payload_str, baseline)
            elif subtype == "graphql_introspection":
                result = await self._test_graphql_introspection(url, method, param_name, payload_str, baseline)
            elif subtype == "dependency_confusion":
                result = await self._test_dependency_confusion(url, method, param_name, payload_str, baseline)
            else:
                result = await self._test_direct_prompt(url, method, param_name, payload_str, baseline)

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

    async def _send_payload(self, url: str, method: str, param_name: str, payload: str) -> dict:
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

    def _create_finding(self, title, description, severity, cvss, confidence, family, subtype, payload, request_data, response_data, evidence):
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

    async def _test_direct_prompt(self, url, method, param_name, payload, baseline):
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None
        body = resp["body"]
        matches = self._match_patterns(body, PROMPT_INJECTION_PATTERNS + DIRECT_PROMPT_PATTERNS)
        if matches:
            return self._create_finding(
                title="Modern - Direct Prompt Injection",
                description=f"Direct prompt injection detected. Patterns: {', '.join(matches[:3])}",
                severity="critical", cvss=9.8, confidence="high",
                family="modern_injection", subtype="direct_prompt",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:5]},
            )
        if payload in body:
            return self._create_finding(
                title="Modern - Direct Prompt Injection (Reflected)",
                description="Prompt injection payload reflected in response.",
                severity="high", cvss=8.1, confidence="medium",
                family="modern_injection", subtype="direct_prompt",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"payload_reflected": True},
            )
        return None

    async def _test_indirect_prompt(self, url, method, param_name, payload, baseline):
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None
        body = resp["body"]
        matches = self._match_patterns(body, INDIRECT_PROMPT_PATTERNS)
        if matches:
            return self._create_finding(
                title="Modern - Indirect Prompt Injection",
                description=f"Indirect prompt injection detected: {', '.join(matches[:3])}",
                severity="critical", cvss=9.8, confidence="medium",
                family="modern_injection", subtype="indirect_prompt",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"matched_patterns": matches[:5]},
            )
        if payload in body and ("<" in payload or "javascript:" in payload):
            return self._create_finding(
                title="Modern - Indirect Prompt Injection (Reflected)",
                description="Indirect prompt payload reflected with HTML/JS context.",
                severity="high", cvss=8.6, confidence="medium",
                family="modern_injection", subtype="indirect_prompt",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"html_context_reflection": True},
            )
        return None

    async def _test_rag_prompt(self, url, method, param_name, payload, baseline):
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None
        body = resp["body"]
        matches = self._match_patterns(body, RAG_INJECTION_PATTERNS)
        if matches:
            return self._create_finding(
                title="Modern - RAG Prompt Injection",
                description=f"RAG prompt injection detected: {', '.join(matches[:3])}",
                severity="critical", cvss=9.8, confidence="medium",
                family="modern_injection", subtype="rag_prompt",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"matched_patterns": matches[:5]},
            )
        if payload in body:
            return self._create_finding(
                title="Modern - RAG Prompt Injection (Reflected)",
                description="RAG injection payload reflected in response.",
                severity="high", cvss=8.1, confidence="low",
                family="modern_injection", subtype="rag_prompt",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"payload_reflected": True},
            )
        return None

    async def _test_prototype_pollution(self, url, method, param_name, payload, baseline):
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None
        body = resp["body"]
        matches = self._match_patterns(body, PROTOTYPE_POLLUTION_PATTERNS)
        if matches:
            return self._create_finding(
                title="Modern - Prototype Pollution",
                description=f"Prototype pollution detected: {', '.join(matches[:3])}",
                severity="high", cvss=8.6, confidence="high",
                family="modern_injection", subtype="prototype_pollution",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"matched_patterns": matches[:5]},
            )
        if "__proto__" in payload and resp["status_code"] != baseline["status_code"]:
            return self._create_finding(
                title="Modern - Prototype Pollution (Anomaly)",
                description="Prototype pollution payload caused status anomaly.",
                severity="high", cvss=7.5, confidence="medium",
                family="modern_injection", subtype="prototype_pollution",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"status_anomaly": True},
            )
        return None

    async def _test_oauth_injection(self, url, method, param_name, payload, baseline):
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None
        body = resp["body"]
        headers = resp["headers"]
        location = headers.get("location", headers.get("Location", ""))
        matches = self._match_patterns(body, OAUTH_INJECTION_PATTERNS)
        header_matches = self._match_patterns(location, OAUTH_INJECTION_PATTERNS) if location else []
        if matches or header_matches:
            return self._create_finding(
                title="Modern - OAuth Injection",
                description=f"OAuth injection detected: {', '.join((matches + header_matches)[:3])}",
                severity="critical", cvss=9.1, confidence="high",
                family="modern_injection", subtype="oauth_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "redirect_location": location[:500] if location else ""},
                evidence={"body_matches": matches[:3], "header_matches": header_matches[:3]},
            )
        if payload in body and ("redirect_uri" in payload or "client_id" in payload or "token" in payload):
            return self._create_finding(
                title="Modern - OAuth Injection (Reflected)",
                description="OAuth injection payload reflected in response.",
                severity="high", cvss=8.1, confidence="medium",
                family="modern_injection", subtype="oauth_injection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"oauth_reflected": True},
            )
        return None

    async def _test_graphql_introspection(self, url, method, param_name, payload, baseline):
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None
        body = resp["body"]
        matches = self._match_patterns(body, GRAPHQL_INTROSPECTION_PATTERNS)
        if matches:
            return self._create_finding(
                title="Modern - GraphQL Introspection",
                description=f"GraphQL introspection detected: {', '.join(matches[:3])}",
                severity="high", cvss=7.5, confidence="high",
                family="modern_injection", subtype="graphql_introspection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"], "body_length": resp["body_length"]},
                evidence={"matched_patterns": matches[:5]},
            )
        if payload in body and ("__schema" in payload or "__type" in payload):
            return self._create_finding(
                title="Modern - GraphQL Introspection (Reflected)",
                description="GraphQL introspection payload reflected.",
                severity="medium", cvss=6.1, confidence="medium",
                family="modern_injection", subtype="graphql_introspection",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"introspection_reflected": True},
            )
        return None

    async def _test_dependency_confusion(self, url, method, param_name, payload, baseline):
        resp = await self._send_payload(url, method, param_name, payload)
        if resp.get("error"):
            return None
        body = resp["body"]
        matches = self._match_patterns(body, DEPENDENCY_CONFUSION_PATTERNS)
        if matches:
            return self._create_finding(
                title="Modern - Dependency Confusion",
                description=f"Dependency confusion detected: {', '.join(matches[:3])}",
                severity="high", cvss=8.1, confidence="medium",
                family="modern_injection", subtype="dependency_confusion",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"matched_patterns": matches[:5]},
            )
        if resp["status_code"] in (401, 403) and baseline["status_code"] not in (401, 403):
            return self._create_finding(
                title="Modern - Dependency Confusion (Auth Error)",
                description="Dependency confusion caused authentication/authorization error.",
                severity="medium", cvss=6.5, confidence="low",
                family="modern_injection", subtype="dependency_confusion",
                payload=payload,
                request_data={"url": url, "method": method, "param": param_name, "payload": payload},
                response_data={"status_code": resp["status_code"]},
                evidence={"auth_error": True},
            )
        return None
