import asyncio
import logging
import time
import uuid
import json
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field

import httpx

from backend.api.websocket import (
    emit_scan_progress,
    emit_finding,
    emit_tool_output,
    emit_scan_error,
)
from backend.config import settings

logger = logging.getLogger(__name__)


@dataclass
class BaselineResult:
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    body_length: int = 0
    response_time: float = 0.0
    error: Optional[str] = None
    dom_xss_signals: Optional[dict] = None


@dataclass
class InjectionResult:
    payload_id: str = ""
    payload_string: str = ""
    family: str = ""
    subtype: str = ""
    mutation: str = ""
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    body_length: int = 0
    response_time: float = 0.0
    delta_from_baseline: float = 0.0
    body_delta: int = 0
    error: Optional[str] = None
    anomaly_detected: bool = False
    anomaly_reasons: list = field(default_factory=list)


@dataclass
class TaskResult:
    element: dict = field(default_factory=dict)
    family: str = ""
    results: list = field(default_factory=list)
    anomalies_found: int = 0
    errors: int = 0
    total_payloads: int = 0
    baseline: Optional[BaselineResult] = None


ANOMALY_THRESHOLDS = {
    "status_code_diff": True,
    "body_length_ratio": 0.20,   # raised to 20% to reduce FP on dynamic pages
    "response_time_ratio": 2.5,   # slightly tighter
    "error_pattern_match": True,
}

# ─────────────────────────────────────────────────────────────────────────────
# SQL Injection — comprehensive DB error messages
# ─────────────────────────────────────────────────────────────────────────────
SQL_ERROR_PATTERNS = [
    # MySQL / MariaDB
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "mysql_num_rows", "mysql_query", "valid mysql result",
    "mysql server version for the right syntax",
    # PostgreSQL
    "pg_query", "pg_exec", "pg_connect", "pg_last_error",
    "postgresql", "psql error", "syntax error at or near",
    "pq: ", "pg::",
    # MSSQL / Azure SQL
    "mssql", "microsoft sql server", "microsoft ole db provider",
    "odbc sql server driver", "unclosed quotation mark",
    "incorrect syntax near", "msg 1064", "msg 102",
    # Oracle
    "ora-0", "ora-1", "quoted string not properly terminated",
    "oracle error", "pl/sql", "oracle database error",
    # SQLite
    "sqlite3", "sqlite_error", "unrecognized token:",
    # Generic ODBC / JDBC
    "microsoft odbc", "jdbc", "sqlstate", "sqlexception",
    "pdo", "odbc driver", "supplied argument is not a valid mysql",
    # Error context words
    "sql syntax", "unterminated string", "unterminated quoted string",
    "db_query", "db_fetch", "database error", "sql error",
]

# ─────────────────────────────────────────────────────────────────────────────
# XSS Reflection — raw tag/handler/protocol markers
# ─────────────────────────────────────────────────────────────────────────────
XSS_REFLECTION_PATTERNS = [
    "<script", "onerror=", "onload=", "onmouseover=", "onfocus=",
    "javascript:", "vbscript:", "data:text/html",
    "alert(", "confirm(", "prompt(",
    "document.cookie", "document.domain", "document.write(",
    "<img ", "<svg ", "<iframe ", "<body ",
    "<input ", "<button ",
]

# ─────────────────────────────────────────────────────────────────────────────
# Command Injection — execution evidence
# ─────────────────────────────────────────────────────────────────────────────
COMMAND_EXEC_PATTERNS = [
    # Unix /etc/passwd and id output
    "uid=", "gid=", "root:", "root:x:0:0", "/bin/bash", "/bin/sh",
    "daemon:", "nobody:", "/etc/passwd",
    # Windows
    "windows_nt", "win32", "system32", "microsoft windows",
    "c:\\windows", "cmd.exe", "volume serial number",
    # PHP info / Server info pages
    "phpinfo()", "[php information]", "[internetserverapi]",
    # Generic command output
    "total 0", "drwxr-xr-x", "-rwxr-xr-x", "command not found",
]

# ─────────────────────────────────────────────────────────────────────────────
# SSTI — template evaluation evidence
# ─────────────────────────────────────────────────────────────────────────────
SSTI_EVAL_PAIRS = [
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("${7*7}", "49"),
    ("*{7*7}", "49"),
    ("@(7*7)", "49"),
    ("#set($x=7*7)$x", "49"),
    ("{{ 'hello' | upper }}", "HELLO"),
    ("{{config}}", "flask"),
    ("{{config.items()}}", "secret"),
]

# ─────────────────────────────────────────────────────────────────────────────
# XXE — file content / SSRF evidence
# ─────────────────────────────────────────────────────────────────────────────
XXE_PATTERNS = [
    "root:x:0:0", "/bin/bash", "daemon:", "nobody:", "/etc/passwd",
    "[boot loader]", "[operating systems]",
    "<?xml", "<!entity", "doctype",
    "internal server error", "xml parse error", "xml parser",
    "entity not allowed", "external entity",
]

# ─────────────────────────────────────────────────────────────────────────────
# Path Traversal — file content leakage
# ─────────────────────────────────────────────────────────────────────────────
PATH_TRAVERSAL_PATTERNS = [
    "root:x:0:0", "/bin/bash", "daemon:", "nobody:", "/etc/passwd",
    "[boot loader]", "[operating systems]", "windows nt",
    "c:\\windows\\system32", "win.ini", "boot.ini",
    "for 16-bit app support", "[mci extensions.bak]",
    "<?php", "<?xml", "<!doctype",
]

# ─────────────────────────────────────────────────────────────────────────────
# SSRF — backend fetch content evidence  
# ─────────────────────────────────────────────────────────────────────────────
SSRF_PATTERNS = [
    # Cloud metadata
    "ami-", "instance-id", "instance-type", "availability-zone",
    "iam/security-credentials", "computeMetadata", "metadata.internal",
    "azure-metadata", "compute/", "network/",
    # Loopback / local responses (fetched by the server itself)
    "server: ", "x-powered-by:", "content-type:", "last-modified:",
    # Internal SSRF indicators in body
    "connection refused", "network unreachable", "failed to connect",
    "getaddrinfo", "no route to host", "timed out",
]

# ─────────────────────────────────────────────────────────────────────────────
# Open Redirect — destination evidence
# ─────────────────────────────────────────────────────────────────────────────
OPEN_REDIRECT_DESTINATIONS = [
    "evil.com", "attacker.com", "http://127.0.0.1", "http://localhost",
    "//evil.com", "javascript:", "data:text/html",
]

# ─────────────────────────────────────────────────────────────────────────────
# XPath Injection — error patterns
# ─────────────────────────────────────────────────────────────────────────────
XPATH_ERROR_PATTERNS = [
    "xpath error", "invalid xpath", "xpathexception",
    "javax.xml.xpath", "saxparseexception", "xslt error",
    "expression must evaluate to a nodeset",
    "function name is null", "undefined xpath function",
    "invalid expression", "syntax error in xpath",
    "compilation error in xpath",
]

# ─────────────────────────────────────────────────────────────────────────────
# NoSQL Injection — operator / error patterns
# ─────────────────────────────────────────────────────────────────────────────
NOSQL_PATTERNS = [
    # MongoDB errors
    "mongoerror", "mongoparseerror", "mongodrivererror",
    "bsontype error", "invalid bson", "bad bson",
    # Operator leakage
    "$where", "$gt", "$ne", "$regex", "$exists",
    # CouchDB / Redis errors
    "couchdb", "redis error", "rediscommand error",
]

# ─────────────────────────────────────────────────────────────────────────────
# HTMLi — rendered unescaped HTML tags
# ─────────────────────────────────────────────────────────────────────────────
HTMLI_PATTERNS = [
    "htmli-probe-9271", "htmli-confirmed", "htmli-break-out",
    "htmli-highlight", "htmli-figure", "htmli-sup", "htmli-attr-injected",
    "injected-preformatted", "injected-code-block", "injected-list-item",
    "injected-quote", "htmli-null", "htmli_marker", "cell-injected",
    "injected content", "<h1>injected", "<b>injected", "<b>htmli",
    "<p>injected_text_probe", "<hr", "<details",
    "<mark>htmli", "<abbr title", "<del>deleted-content-htmli",
    "<blockquote>injected", "<marquee>", "<blink>", "<pre>injected",
]

# ─────────────────────────────────────────────────────────────────────────────
# TextI — plain-text spoofed content
# ─────────────────────────────────────────────────────────────────────────────
TEXTI_PATTERNS = [
    "texti-probe-7734", "texti-spoofed-message", "texti-confirm",
    "texti-7734", "texti_marker_x9k2", "texti-special",
    "texti-injected", "texti-null", "injected_paragraph",
    "texti-confirmed", "account suspended - texti",
    "injected-text-line", "injected-body:", "injected_section",
]

# ─────────────────────────────────────────────────────────────────────────────
# LDAP — error patterns
# ─────────────────────────────────────────────────────────────────────────────
LDAPI_PATTERNS = [
    "ldap", "ldaperror", "invalid dn", "ldap_bind", "ldap_search",
    "javax.naming", "ldapexception", "invalid credentials",
    "ldap error", "0x31", "constraint violation", "sizelimitexceeded",
    "directory services", "active directory", "com.sun.jndi",
    "invalid filter syntax", "bad search filter", "ldap://",
]

# ─────────────────────────────────────────────────────────────────────────────
# DOM-XSS — JS source→sink markers
# ─────────────────────────────────────────────────────────────────────────────
DOM_XSS_JS_SOURCES = [
    "location.search", "location.hash", "location.href", "location.pathname",
    "document.url", "document.referrer", "document.documenturi",
    "window.name", "location.origin", "document.location",
    "window.location", "history.pushstate", "history.replacestate",
]

DOM_XSS_JS_SINKS = [
    "innerhtml", "outerhtml", "document.write(", "document.writeln(",
    "eval(", "settimeout(", "setinterval(", "execscript(",
    ".html(", "$.html(", "location.href =", "location.replace(",
    "location.assign(", "insertadjacenthtml", "createelement(",
    ".src =", ".href =", "srcdoc",
]

# ─────────────────────────────────────────────────────────────────────────────
# Object Injection — deserialization / EL evaluation
# ─────────────────────────────────────────────────────────────────────────────
OBJECT_INJECTION_PATTERNS = [
    "java.lang.runtime", "processbuilder", "unserialize", "__wakeup", "__destruct",
    "serialization of", "__php_incomplete_class", "elexception", "el.evaluationexception",
    "spelevaluationexception", "expressionfactory", "javax.el", "illegalstateexception",
    "invocationtargetexception", "obj_inject!",
    # Python pickle
    "reduce", "__reduce__", "copyreg",
    # Ruby Marshal
    "marshal.load", "activesupport::deprecation",
    # PHP phar
    "phar://",
]

# ─────────────────────────────────────────────────────────────────────────────
# XML / XSLT Injection
# ─────────────────────────────────────────────────────────────────────────────
XML_INJECTION_PATTERNS = [
    "xml parse error", "saxon", "xsltproc", "xalan", "system-property",
    "unparsed-entity-uri", "document()", "xsl:value-of", "xml parser", "libxml",
    "javax.xml.transform", "org.xml.sax", "sax parser", "expat error",
    "malformed xml", "entity expansion", "billion laughs",
]

# ─────────────────────────────────────────────────────────────────────────────
# Protocol Injection (SMTP/IMAP/POP3)
# ─────────────────────────────────────────────────────────────────────────────
PROTOCOL_INJECTION_PATTERNS = [
    "smtp error", "imap error", "pop3 error", "mail delivery failed",
    "220 smtp", "220 mail", "250 ok", "354 start mail input",
    "bad command", "invalid command", "auth required", "auth login",
    "rcpt to:", "mail from:", "data\r\n",
]

# ─────────────────────────────────────────────────────────────────────────────
# Parameter Pollution
# ─────────────────────────────────────────────────────────────────────────────
PARAMETER_POLLUTION_PATTERNS = [
    "mass assignment", "unpermitted parameter", "unknown attribute",
    "duplicate parameter", "parameter pollution", "array to string conversion",
    "type error", "type mismatch", "keyerror", "attributeerror",
    "invalid type", "unexpected field",
]

# ─────────────────────────────────────────────────────────────────────────────
# Log Injection
# ─────────────────────────────────────────────────────────────────────────────
LOG_INJECTION_PATTERNS = [
    "[critical] admin login bypassed", "[error] database corruption detected",
    "[info] user 'admin' password reset successful", "texti-injected",
    "injected-header", "log injection", "newline injection",
    "crlf injection", "log forging",
]

# ─────────────────────────────────────────────────────────────────────────────
# Prompt Injection
# ─────────────────────────────────────────────────────────────────────────────
PROMPT_INJECTION_PATTERNS = [
    "injected_1337", "ignore all previous instructions",
    "developer mode", "jailbreak", "dan mode",
    "system prompt", "<|system|>",
    "you are now", "act as", "pretend you are",
    "disregard your previous",
]

# ─────────────────────────────────────────────────────────────────────────────
# Modern Injection (Prototype pollution, GraphQL, OAuth, Supply chain)
# ─────────────────────────────────────────────────────────────────────────────
MODERN_INJECTION_PATTERNS = [
    "__proto__", "constructor.prototype", "polluted",
    "redirect_uri", "access_token", "id_token",
    "__schema", "introspectionquery", "__typename",
    "dependency confusion", "package.json", "requirements.txt",
    "node_modules", "prototype pollution",
]

# ─────────────────────────────────────────────────────────────────────────────
# CSS Injection
# ─────────────────────────────────────────────────────────────────────────────
CSS_INJECTION_PATTERNS = [
    "css_injected_content", "css_probe", "css_probe_attr",
    "expression(", "behavior:", "moz-binding:",
    "@import", "url(javascript:", "-moz-binding",
]

# ─────────────────────────────────────────────────────────────────────────────
# SSI Injection
# ─────────────────────────────────────────────────────────────────────────────
SSI_INJECTION_PATTERNS = [
    "[ssi_error_injected]", "injected_ssi_1337",
    "<!--#echo", "<!--#exec", "<!--#include",
    "ssi error", "server-side include",
]

# ─────────────────────────────────────────────────────────────────────────────
# Regex / ReDoS
# ─────────────────────────────────────────────────────────────────────────────
REGEX_INJECTION_PATTERNS = [
    "regular expression runtime", "regex execution time",
    "backtrack limit", "pcre_exec", "re error", "preg_match",
    "invalid regex", "regex syntax error",
]

# ─────────────────────────────────────────────────────────────────────────────
# PDF Injection
# ─────────────────────────────────────────────────────────────────────────────
PDF_INJECTION_PATTERNS = [
    "%pdf-", "endobj", "endstream", "/type /page", "/catalog",
    "application/pdf", "%pdf", "obj\n",
]

# ─────────────────────────────────────────────────────────────────────────────
# Email Header Injection
# ─────────────────────────────────────────────────────────────────────────────
EMAIL_INJECTION_PATTERNS = [
    "to: attacker@", "cc: attacker@", "bcc: attacker@",
    "smtp error", "mail delivery", "message-id:",
    "content-type: text/plain", "x-mailer:",
    "received: from", "relay access denied",
]

# ─────────────────────────────────────────────────────────────────────────────
# Header Injection / CRLF
# ─────────────────────────────────────────────────────────────────────────────
HEADER_INJECTION_PATTERNS = [
    "set-cookie: injected", "x-injected:", "injected-header:",
    "location: javascript:", "refresh: 0;url=",
    "x-forwarded-for: injected", "via: injected",
]

# ─────────────────────────────────────────────────────────────────────────────
# Formula Injection (CSV/Spreadsheet)
# ─────────────────────────────────────────────────────────────────────────────
FORMULA_INJECTION_PATTERNS = [
    "=cmd|", "=system(", "=hyperlink(", "#ref!", "#name?",
    "spreadsheetml", "calculation error", "formula error",
    "dde://", "msexcel",
]

class Executor:
    def __init__(
        self,
        scan_id: str,
        config: Optional[dict] = None,
        concurrency: int = 15,
        rate_limit: int = 30,
        timeout: int = 30,
    ):
        self.scan_id = scan_id
        self.config = config or {}
        self.concurrency = concurrency
        self.rate_limit = rate_limit
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrency)
        self._min_interval = 1.0 / max(rate_limit, 1)
        self._last_request_time = 0.0
        self._requests_sent = 0
        self._findings_count = 0
        self._total_tasks = 0
        self._completed_tasks = 0
        self._cancelled = False
        self._headers = self.config.get("custom_headers", {})
        from urllib.parse import urlparse
        target_netloc = urlparse(str(self.config.get("target_url", "")) or "").netloc.lower()
        self._target_domain = target_netloc.split(":")[0] if target_netloc else ""
        self._verify_ssl = self.config.get("verify_ssl", False)
        self._client: Optional[httpx.AsyncClient] = None
        self._pause_event: Optional[asyncio.Event] = None
        self._stop_event: Optional[asyncio.Event] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                verify=self._verify_ssl,
                timeout=httpx.Timeout(self.timeout, connect=10.0),
                follow_redirects=True,
                headers={"User-Agent": "InjectGuard-Scanner/1.0", **self._headers},
                limits=httpx.Limits(max_connections=50, max_keepalive_connections=10),
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _rate_wait(self):
        if self._min_interval > 0:
            now = time.monotonic()
            wait = self._last_request_time + self._min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_time = max(time.monotonic(), self._last_request_time + self._min_interval)

    async def execute_plan(self, plan, pause_event=None, stop_event=None) -> list[TaskResult]:
        self._pause_event = pause_event
        self._stop_event = stop_event
        self._total_tasks = len(plan.tasks)
        self._completed_tasks = 0

        await emit_tool_output(
            self.scan_id, "attack_engine",
            f"Starting parallel attack: {self._total_tasks} tasks "
            f"across {plan.total_families} families, "
            f"{plan.total_payloads} total payloads "
            f"(concurrency={self.concurrency}, rate={self.rate_limit}/s)",
        )

        results: list[TaskResult] = []
        queue: asyncio.Queue = asyncio.Queue()
        for task in plan.tasks:
            await queue.put(task)

        lock = asyncio.Lock()
        progress_counter = [0]

        async def worker():
            while not queue.empty():
                if self._stop_check():
                    return
                await self._pause_check()
                try:
                    task = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return

                task_result = await self._execute_task(task)
                async with lock:
                    results.append(task_result)
                    self._completed_tasks += 1
                    progress_counter[0] += 1
                    # emit progress every 3 tasks to avoid socket spam
                    if progress_counter[0] % 3 == 0 or queue.empty():
                        pct = (self._completed_tasks / max(self._total_tasks, 1)) * 100
                        await emit_scan_progress(
                            self.scan_id,
                            {
                                "phase": "executing",
                                "percentage": round(pct, 1),
                                "requests_sent": self._requests_sent,
                                "findings_count": self._findings_count,
                                "current_tool": f"attack_{task.family}",
                            },
                        )
                queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        await asyncio.gather(*workers, return_exceptions=True)

        await emit_scan_progress(
            self.scan_id,
            {
                "phase": "executing",
                "percentage": 100.0,
                "requests_sent": self._requests_sent,
                "findings_count": self._findings_count,
            },
        )
        await emit_tool_output(
            self.scan_id, "attack_engine",
            f"Attack execution complete: {self._findings_count} anomalies found in {self._requests_sent} requests",
        )
        return results

    def _stop_check(self) -> bool:
        if self._cancelled:
            return True
        if self._stop_event and self._stop_event.is_set():
            return True
        return False

    async def _pause_check(self):
        if self._pause_event and not self._pause_event.is_set():
            await emit_tool_output(self.scan_id, "attack_engine", "Attack paused", "warn")
            await self._pause_event.wait()
            await emit_tool_output(self.scan_id, "attack_engine", "Attack resumed", "info")

    async def _execute_task(self, task) -> TaskResult:
        result = TaskResult(
            element=task.element,
            family=task.family,
            total_payloads=len(task.payloads),
        )

        element = task.element
        url = element.get("url", "")
        param_name = element.get("parameter_name", "")
        http_method = element.get("http_method", "GET").upper()
        context = element.get("context", "string")
        form_fields = element.get("form_fields", [])

        if self._target_domain:
            from urllib.parse import urlparse
            el_host = urlparse(url).netloc.split(":")[0].lower()
            in_scope = (
                el_host == self._target_domain
                or el_host.endswith("." + self._target_domain)
            )
            if not in_scope:
                return result

        try:
            baseline = await self._capture_baseline(url, http_method, param_name, form_fields)
        except Exception as e:
            logger.error(f"Baseline capture failed for {url}: {e}")
            result.results.append(InjectionResult(error=f"Baseline failed: {str(e)}"))
            result.errors += 1
            return result
        result.baseline = baseline

        payload_coros = [
            self._inject_and_analyze(url, http_method, param_name, context, payload, baseline, form_fields)
            for payload in task.payloads
        ]
        try:
            injection_results = await asyncio.wait_for(
                asyncio.gather(*payload_coros, return_exceptions=True),
                timeout=max(60, len(task.payloads) * 15),
            )
        except asyncio.TimeoutError:
            for coro in payload_coros:
                coro.close()
            injection_results = [InjectionResult(error="task timeout")]

        for ir in injection_results:
            if isinstance(ir, Exception):
                result.errors += 1
                result.results.append(InjectionResult(error=f"Execution error: {str(ir)}"))
            elif isinstance(ir, InjectionResult):
                result.results.append(ir)
                if ir.anomaly_detected:
                    result.anomalies_found += 1
                    await self._handle_anomaly(task, ir, baseline)

        return result

    async def _capture_baseline(self, url: str, method: str, param_name: str, form_fields: list = None) -> BaselineResult:
        async with self._semaphore:
            if self._stop_check():
                return BaselineResult(error="Scan stopped by user")
            await self._pause_check()
            await self._rate_wait()
            start_time = datetime.utcnow()
            try:
                client = await self._get_client()
                if method == "GET":
                    response = await client.get(url)
                else:
                    # POST: include all form fields, testing the target param
                    data = {}
                    if form_fields:
                        for f in form_fields:
                            data[f.get("name", "")] = f.get("value", "")
                    data[param_name] = "test"
                    response = await client.post(url, data=data)
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                self._requests_sent += 1
                body_text = response.text[:200_000]
                baseline = BaselineResult(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=body_text,
                    body_length=len(response.text),
                    response_time=elapsed,
                )
                # ── Static DOM-XSS analysis on the baseline page ──
                # Detect source→sink data flows in the page's JS regardless of
                # whether any payload was injected — this catches frameworks that
                # pass location.search directly into innerHTML/document.write.
                body_lower = body_text.lower()
                sources_in_js = [s for s in DOM_XSS_JS_SOURCES if s in body_lower]
                sinks_in_js = [s for s in DOM_XSS_JS_SINKS if s in body_lower]
                if sources_in_js and sinks_in_js:
                    baseline.dom_xss_signals = {
                        "sources": sources_in_js,
                        "sinks": sinks_in_js,
                    }
                else:
                    baseline.dom_xss_signals = None
                return baseline
            except Exception as e:
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                return BaselineResult(error=str(e), response_time=elapsed)

    async def _inject_and_analyze(
        self, url: str, method: str, param_name: str, context: str,
        payload: dict, baseline: BaselineResult, form_fields: list = None,
    ) -> InjectionResult:
        async with self._semaphore:
            if self._stop_check():
                return InjectionResult(error="Scan stopped by user")
            await self._pause_check()
            await self._rate_wait()
            result = InjectionResult(
                payload_id=payload.get("id", ""),
                payload_string=payload.get("payload_string", ""),
                family=payload.get("family", ""),
                subtype=payload.get("subtype", ""),
                mutation=payload.get("mutation", "original"),
            )
            payload_str = payload.get("payload_string", "")

            try:
                start_time = datetime.utcnow()
                client = await self._get_client()

                if method == "GET" or context in ("string", "html", "template"):
                    from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
                    parsed = urlparse(url)
                    existing_params = parse_qs(parsed.query)
                    existing_params[param_name] = [payload_str]
                    new_query = urlencode(existing_params, doseq=True)
                    inject_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment,
                    ))
                    response = await client.get(inject_url)
                elif context == "json":
                    response = await client.post(
                        url,
                        json={param_name: payload_str},
                        headers={"Content-Type": "application/json"},
                    )
                elif context == "header":
                    hdrs = dict(self._headers)
                    hdrs[param_name] = payload_str
                    response = await client.get(url, headers=hdrs)
                elif context == "cookie":
                    response = await client.get(url, cookies={param_name: payload_str})
                elif context == "xml":
                    xml_body = f'<?xml version="1.0"?><root><{param_name}>{payload_str}</{param_name}></root>'
                    response = await client.post(
                        url, content=xml_body,
                        headers={"Content-Type": "application/xml"},
                    )
                else:
                    # POST form: include all form fields, replace target param with payload
                    data = {}
                    if form_fields:
                        for f in form_fields:
                            data[f.get("name", "")] = f.get("value", "")
                    data[param_name] = payload_str
                    response = await client.request(
                        method, url, data=data,
                    )

                elapsed = (datetime.utcnow() - start_time).total_seconds()
                self._requests_sent += 1

                result.status_code = response.status_code
                result.headers = dict(response.headers)
                result.body = response.text[:200_000]
                result.body_length = len(response.text)
                result.response_time = elapsed

            except httpx.TimeoutException:
                result.error = "Request timed out"
                result.response_time = self.timeout
                return result
            except httpx.ConnectError as e:
                result.error = f"Connection error: {str(e)}"
                return result
            except Exception as e:
                result.error = f"Request error: {str(e)}"
                return result

            if baseline.error:
                result.anomaly_detected = True
                result.anomaly_reasons.append("baseline_error")
                return result

            result.delta_from_baseline = abs(result.response_time - baseline.response_time)
            result.body_delta = abs(result.body_length - baseline.body_length)

            anomalies = self._detect_anomalies(result, baseline)

            # Propagate static DOM-XSS signal from baseline to this result so
            # the orchestrator's analyze phase picks it up as a confirmed finding.
            if (
                result.family == "xss"
                and baseline.dom_xss_signals
                and "dom_xss_dataflow" not in anomalies
            ):
                anomalies.append("dom_xss_dataflow")

            if anomalies:
                result.anomaly_detected = True
                result.anomaly_reasons = anomalies
            return result

    def _detect_anomalies(self, result: InjectionResult, baseline: BaselineResult) -> list[str]:  # noqa: C901
        anomalies = []

        # ── Generic structural signals ────────────────────────────────────────
        if result.status_code != baseline.status_code:
            if result.status_code in (200, 500, 403, 301, 302) and baseline.status_code in (200, 400, 404):
                anomalies.append("status_code_change")

        if baseline.body_length > 0:
            length_ratio = abs(result.body_length - baseline.body_length) / baseline.body_length
            if length_ratio > ANOMALY_THRESHOLDS["body_length_ratio"]:
                anomalies.append("body_length_significant_change")

        if baseline.response_time > 0:
            time_ratio = result.response_time / baseline.response_time
            if time_ratio > ANOMALY_THRESHOLDS["response_time_ratio"]:
                anomalies.append("response_time_spike")

        if not result.body:
            return anomalies

        body_lower = result.body.lower()
        family = result.family
        payload_lower = (result.payload_string or "").lower()
        resp_headers_str = " ".join(f"{k}: {v}" for k, v in result.headers.items()).lower()

        # ── SQL Injection ────────────────────────────────────────────────────
        if family == "sqli":
            for pattern in SQL_ERROR_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("sql_error_disclosure")
                    break
            # Time-based blind: sleep payloads cause measurable delay
            if result.delta_from_baseline > 4.0:
                anomalies.append("blind_sqli_time_delay_confirmed")
            # Boolean blind: same-size responses that differ when True vs False
            if result.status_code != baseline.status_code:
                anomalies.append("sqli_boolean_status_diff")

        # ── XSS ─────────────────────────────────────────────────────────────
        elif family == "xss":
            _xss_unescaped = False
            for pattern in XSS_REFLECTION_PATTERNS:
                pat_low = pattern.lower()
                if pat_low in payload_lower and pat_low in body_lower:
                    escaped = pat_low.replace("<", "&lt;").replace(">", "&gt;")
                    if escaped not in body_lower:
                        _xss_unescaped = True
                        break
            if _xss_unescaped:
                anomalies.append("xss_reflection")

        # ── Command Injection ────────────────────────────────────────────────
        elif family == "cmdi":
            for pattern in COMMAND_EXEC_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("command_execution_evidence")
                    break
            if result.delta_from_baseline > 4.0:
                anomalies.append("blind_cmdi_time_delay_confirmed")

        # ── SSTI ─────────────────────────────────────────────────────────────
        elif family == "ssti":
            # Check all known math-eval pairs
            for probe_payload, expected_output in SSTI_EVAL_PAIRS:
                if (probe_payload.lower() in payload_lower and
                        expected_output.lower() in body_lower and
                        probe_payload.lower() not in body_lower):  # output ≠ raw payload echoed
                    anomalies.append("template_injection_reflection")
                    break
            # Fallback: raw payload echoed back means no evaluation (not confirmed)
            # Detect config/object dump
            if "flask" in body_lower and "secret" in body_lower:
                if "template_injection_reflection" not in anomalies:
                    anomalies.append("template_injection_reflection")

        # ── XXE ──────────────────────────────────────────────────────────────
        elif family == "xxe":
            for pattern in XXE_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("xxe_file_content")
                    break
            # Error-based XXE: entity parsing errors
            if "xml" in body_lower and ("error" in body_lower or "exception" in body_lower):
                if "xxe_file_content" not in anomalies:
                    anomalies.append("xxe_parse_error")

        # ── SSRF ─────────────────────────────────────────────────────────────
        elif family == "ssrf":
            for pattern in SSRF_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("ssrf_response_content")
                    break
            # SSRF via redirect: server redirected to our internal URL
            location_hdr = result.headers.get("location", "").lower()
            if location_hdr and any(d in location_hdr for d in ["127.0.0.1", "localhost", "169.254", "metadata"]):
                anomalies.append("ssrf_redirect_detected")
            # Out-of-band: response body referencing our callback URL
            if "evil.com" in body_lower or "ssrf-callback" in body_lower:
                anomalies.append("ssrf_oob_callback")

        # ── Open Redirect ────────────────────────────────────────────────────
        elif family == "open_redirect":
            # Check Location header — most reliable
            location_hdr = result.headers.get("location", "")
            for dest in OPEN_REDIRECT_DESTINATIONS:
                if dest.lower() in location_hdr.lower():
                    anomalies.append("open_redirect_confirmed")
                    break
            # Also check body
            if "open_redirect_confirmed" not in anomalies:
                for dest in OPEN_REDIRECT_DESTINATIONS:
                    if dest.lower() in body_lower:
                        anomalies.append("open_redirect_body_leak")
                        break
            # 3xx to external
            if result.status_code in (301, 302, 303, 307, 308):
                loc = result.headers.get("location", "")
                if loc and not loc.startswith("/") and "evil.com" in loc.lower():
                    anomalies.append("open_redirect_confirmed")

        # ── NoSQL Injection ──────────────────────────────────────────────────
        elif family == "nosql":
            for pattern in NOSQL_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("nosql_operator_detected")
                    break
            # Auth bypass: response grew significantly (returned more records)
            if result.body_delta > 300 and result.status_code == 200:
                if "nosql_operator_detected" not in anomalies:
                    anomalies.append("nosql_auth_bypass_possible")
            # Status changed from 401/403 to 200 → auth bypass
            if baseline.status_code in (401, 403) and result.status_code == 200:
                anomalies.append("nosql_auth_bypass_possible")

        # ── XPath Injection ──────────────────────────────────────────────────
        elif family == "xpath":
            for pattern in XPATH_ERROR_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("xpath_error_disclosure")
                    break
            # Auth bypass via true condition
            if baseline.status_code in (401, 403) and result.status_code == 200:
                anomalies.append("xpath_auth_bypass")
            # Response body grew significantly
            if result.body_delta > 200 and result.status_code == 200:
                if "xpath_error_disclosure" not in anomalies:
                    anomalies.append("xpath_boolean_response_change")

        # ── Path Traversal ───────────────────────────────────────────────────
        elif family == "path_traversal":
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("path_traversal_file_content")
                    break
            # PHP warnings from traversal
            if "failed to open stream" in body_lower or "no such file" in body_lower:
                if "path_traversal_file_content" not in anomalies:
                    anomalies.append("path_traversal_error_disclosure")

        # ── HTMLi ────────────────────────────────────────────────────────────
        elif family == "htmli":
            for pattern in HTMLI_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("html_injection_rendered")
                    break
            # Also check if any injected raw HTML tag appears unescaped
            if "html_injection_rendered" not in anomalies:
                for raw_tag in ("<h1>", "<b>", "<img", "<svg", "<form", "<marquee>", "<blink>"):
                    if raw_tag in payload_lower and raw_tag in body_lower:
                        escaped_tag = raw_tag.replace("<", "&lt;").replace(">", "&gt;")
                        if escaped_tag not in body_lower:
                            anomalies.append("html_injection_rendered")
                            break

        # ── Text Injection / CRLF ─────────────────────────────────────────────
        elif family == "texti":
            for pattern in TEXTI_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("text_injection_reflected")
                    break
            # CRLF: check for injected headers in both response headers and body
            payload_str = result.payload_string or ""
            if "\r\n" in payload_str or "%0d%0a" in payload_str.lower():
                if "texti-injected" in resp_headers_str or "injected-header" in resp_headers_str:
                    anomalies.append("crlf_header_injection")
                # Double CRLF: body injection
                if "injected-body:" in body_lower or "texti-injected" in body_lower:
                    anomalies.append("crlf_body_injection")

        # ── LDAP Injection ────────────────────────────────────────────────────
        elif family == "ldapi":
            for pattern in LDAPI_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("ldap_error_disclosure")
                    break
            if result.body_delta > 400 and result.status_code == 200:
                anomalies.append("ldap_response_anomaly")
            if baseline.status_code in (401, 403) and result.status_code == 200:
                anomalies.append("ldap_auth_bypass")

        # ── Object / Deserialization Injection ────────────────────────────────
        elif family == "object_injection":
            for pattern in OBJECT_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("object_injection_detected")
                    break
            # EL evaluation: arithmetic results
            for probe, expected in [("${7*7}", "49"), ("#{7*7}", "49"),
                                     ("${7*'7'}", "7777777"), ("*{7*7}", "49")]:
                if probe.lower() in payload_lower and expected in result.body:
                    anomalies.append("el_evaluation_detected")
                    break
            # Java RCE evidence via time delay
            if result.delta_from_baseline > 5.0:
                if "object_injection_detected" not in anomalies:
                    anomalies.append("object_injection_time_delay")

        # ── XML Injection ─────────────────────────────────────────────────────
        elif family == "xml_injection":
            for pattern in XML_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("xml_injection_detected")
                    break
            if "xml" in body_lower and "error" in body_lower:
                if "xml_injection_detected" not in anomalies:
                    anomalies.append("xml_parse_error")

        # ── Protocol Injection (SMTP/IMAP) ────────────────────────────────────
        elif family == "protocol_injection":
            for pattern in PROTOCOL_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("protocol_injection_detected")
                    break

        # ── Parameter Pollution ───────────────────────────────────────────────
        elif family == "parameter_pollution":
            for pattern in PARAMETER_POLLUTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("parameter_pollution_detected")
                    break
            # Behavioral: response size changed significantly after duplicate params
            if result.body_delta > 100 and result.status_code != baseline.status_code:
                if "parameter_pollution_detected" not in anomalies:
                    anomalies.append("parameter_pollution_behavioral")

        # ── Log Injection ─────────────────────────────────────────────────────
        elif family == "log_injection":
            for pattern in LOG_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("log_injection_detected")
                    break
            # CRLF in logs: check reflected newline sequences
            if "\n" in (result.payload_string or ""):
                if "log_injection_detected" not in anomalies and "injected" in body_lower:
                    anomalies.append("log_injection_reflected")

        # ── Prompt Injection ──────────────────────────────────────────────────
        elif family == "prompt_injection":
            if "injected_1337" in body_lower:
                anomalies.append("prompt_injection_confirmed")
            else:
                for pattern in PROMPT_INJECTION_PATTERNS:
                    if pattern.lower() in body_lower:
                        anomalies.append("prompt_injection_echoed")
                        break

        # ── Modern Injection (Prototype, GraphQL, OAuth) ──────────────────────
        elif family == "modern_injection":
            for pattern in MODERN_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("modern_injection_detected")
                    break
            if "polluted" in body_lower and "injected_1337" in body_lower:
                anomalies.append("prototype_pollution_confirmed")
            # GraphQL introspection returned schema
            if "__schema" in body_lower and "types" in body_lower:
                anomalies.append("graphql_introspection_exposed")

        # ── CSS Injection ─────────────────────────────────────────────────────
        elif family == "css_injection":
            for pattern in CSS_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("css_injection_detected")
                    break
            # CSS reflected into a <style> context
            if "<style" in body_lower and payload_lower in body_lower:
                if "css_injection_detected" not in anomalies:
                    anomalies.append("css_injection_in_style_tag")

        # ── SSI Injection ─────────────────────────────────────────────────────
        elif family == "ssi_injection":
            for pattern in SSI_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("ssi_injection_detected")
                    break
            for pattern in COMMAND_EXEC_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("command_execution_evidence")
                    break
            # Apache/nginx SSI date/time output
            if "<!--#echo" in body_lower or "date_local" in body_lower:
                if "ssi_injection_detected" not in anomalies:
                    anomalies.append("ssi_echo_executed")

        # ── Null Byte Injection ───────────────────────────────────────────────
        elif family == "null_byte":
            if "warning: null byte" in body_lower or "invalid byte sequence" in body_lower:
                anomalies.append("null_byte_error_detected")
            elif "unexpected end of file" in body_lower or "string not properly terminated" in body_lower:
                anomalies.append("null_byte_error_detected")
            elif result.status_code == 200 and baseline.status_code in (403, 404):
                # Null-byte truncated path restriction
                anomalies.append("null_byte_bypass_possible")
            elif "admin" in body_lower and "%00" in payload_lower:
                anomalies.append("null_byte_truncation_possible")

        # ── Unicode Injection ─────────────────────────────────────────────────
        elif family == "unicode_injection":
            # Homograph: response shows privileged content it shouldn't
            if result.status_code == 200 and baseline.status_code in (403, 404, 401):
                anomalies.append("unicode_bypass_possible")
            elif "admin" in body_lower and "admin" not in baseline.body.lower():
                anomalies.append("unicode_homograph_spoofed")

        # ── Regex / ReDoS ─────────────────────────────────────────────────────
        elif family == "regex_injection":
            for pattern in REGEX_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("regex_error_detected")
                    break
            # ReDoS threshold: 5 s absolute OR 3x slower than baseline
            if result.response_time > 5.0 or result.delta_from_baseline > 4.0:
                anomalies.append("redos_timeout_possible")

        # ── PDF Injection ──────────────────────────────────────────────────────
        elif family == "pdf_injection":
            for pattern in PDF_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("pdf_structure_leaked")
                    break
            # PDF MIME type in response
            ct = result.headers.get("content-type", "").lower()
            if "application/pdf" in ct:
                anomalies.append("pdf_structure_leaked")

        # ── Email Header Injection ─────────────────────────────────────────────
        elif family == "email_injection":
            for pattern in EMAIL_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("email_header_injection_detected")
                    break
            # Injected header in SMTP response
            if "email_header_injection_detected" not in anomalies:
                for pattern in EMAIL_INJECTION_PATTERNS:
                    if pattern.lower() in resp_headers_str:
                        anomalies.append("email_header_injection_in_headers")
                        break

        # ── Header Injection / CRLF ────────────────────────────────────────────
        elif family == "header_injection":
            for pattern in HEADER_INJECTION_PATTERNS:
                if pattern.lower() in resp_headers_str:
                    anomalies.append("header_injection_detected")
                    break
            for pattern in HEADER_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    if "header_injection_detected" not in anomalies:
                        anomalies.append("header_injection_in_body")
                    break
            # CRLF: injected Set-Cookie or Location
            if "\r\n" in (result.payload_string or "") or "%0d%0a" in payload_lower:
                if "set-cookie" in resp_headers_str or "location" in resp_headers_str:
                    anomalies.append("crlf_header_split")

        # ── Formula / CSV Injection ────────────────────────────────────────────
        elif family == "formula_injection":
            for pattern in FORMULA_INJECTION_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("formula_injection_detected")
                    break
            # DDE link echoed in response
            if "=cmd|" in result.body or "=dde(" in body_lower:
                if "formula_injection_detected" not in anomalies:
                    anomalies.append("formula_injection_detected")

        # ── Code Injection ─────────────────────────────────────────────────────
        elif family == "code_injection":
            # Check for eval output — arithmetic
            for probe, expected in [("7*7", "49"), ("7+7", "14"), ("pow(2,10)", "1024")]:
                if probe in payload_lower and expected in result.body:
                    anomalies.append("code_injection_eval_detected")
                    break
            for pattern in COMMAND_EXEC_PATTERNS:
                if pattern.lower() in body_lower:
                    anomalies.append("command_execution_evidence")
                    break
            if result.delta_from_baseline > 4.0:
                anomalies.append("code_injection_time_delay")

        # ── CRLF (dedicated family) ────────────────────────────────────────────
        elif family == "crlf":
            payload_str = result.payload_string or ""
            if "\r\n" in payload_str or "%0d%0a" in payload_str.lower():
                # Check injected header appeared in response headers
                for injected_hdr in ["x-injected", "injected-header", "texti-injected", "set-cookie: injected"]:
                    if injected_hdr in resp_headers_str:
                        anomalies.append("crlf_header_injection")
                        break
                if "crlf_header_injection" not in anomalies and "injected" in body_lower:
                    anomalies.append("crlf_body_injection")

        # ── Generic fallback: payload reflected verbatim ───────────────────────
        if not anomalies and result.payload_string and len(result.payload_string) > 3:
            if result.payload_string in result.body:
                anomalies.append("payload_reflected")

        return anomalies


    async def _handle_anomaly(self, task, result: InjectionResult, baseline: BaselineResult):
        self._findings_count += 1
        severity = self._determine_severity(result)
        confidence = self._determine_confidence(result)

        finding = {
            "id": str(uuid.uuid4()),
            "title": f"{result.family.upper()} - {result.subtype} in {task.element.get('parameter_name', 'unknown')}",
            "description": self._generate_description(result),
            "severity": severity,
            "confidence": confidence,
            "injection_family": result.family,
            "injection_subtype": result.subtype,
            "affected_url": task.element.get("url", ""),
            "affected_parameter": task.element.get("parameter_name", ""),
            "payload": result.payload_string,
            "mutation": result.mutation,
            "evidence": {
                "status_code": result.status_code,
                "body_delta": result.body_delta,
                "response_time_delta": result.delta_from_baseline,
                "anomaly_reasons": result.anomaly_reasons,
                "baseline_status": baseline.status_code,
                "baseline_body_length": baseline.body_length,
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

        await emit_finding(self.scan_id, finding)
        await emit_tool_output(
            self.scan_id, "attack_engine",
            f"[{severity.upper()}] {finding['title']} — {', '.join(result.anomaly_reasons)}",
        )

    def _determine_severity(self, result: InjectionResult) -> str:
        severity_map = {
            # Critical — direct server compromise or data exfiltration
            "sqli": "critical", "cmdi": "critical", "ssti": "critical",
            "code_injection": "critical", "ldapi": "critical",
            "object_injection": "critical",
            # High — significant impact, data exposure
            "xxe": "high", "ssrf": "high", "xss": "high",
            "nosql": "high", "xpath": "high", "path_traversal": "high",
            "ssi_injection": "high", "xml_injection": "high",
            # Medium
            "open_redirect": "medium", "crlf": "medium",
            "header_injection": "medium", "email_injection": "medium",
            "formula_injection": "medium", "htmli": "medium",
            "parameter_pollution": "medium", "css_injection": "medium",
            "protocol_injection": "medium", "modern_injection": "medium",
            # Low / Info
            "texti": "low", "log_injection": "low",
            "null_byte": "low", "unicode_injection": "low",
            "regex_injection": "low", "pdf_injection": "low",
            "prompt_injection": "low",
        }
        base = severity_map.get(result.family, "info")

        reasons = result.anomaly_reasons
        # Hard evidence overrides — strongest signals
        if any(r in reasons for r in (
            "sql_error_disclosure", "command_execution_evidence",
            "template_injection_reflection", "ldap_error_disclosure",
            "el_evaluation_detected", "code_injection_eval_detected",
            "object_injection_detected",
        )):
            return "critical"
        if any(r in reasons for r in (
            "xxe_file_content", "path_traversal_file_content",
            "ssrf_response_content", "ssrf_redirect_detected",
            "nosql_auth_bypass_possible", "ldap_auth_bypass",
            "xpath_auth_bypass", "dom_xss_dataflow", "xss_reflection",
            "ssi_injection_detected", "ssi_echo_executed",
            "html_injection_rendered",
        )):
            return "high"
        if any(r in reasons for r in (
            "open_redirect_confirmed", "nosql_operator_detected",
            "crlf_header_injection", "crlf_header_split",
            "header_injection_detected", "email_header_injection_detected",
            "formula_injection_detected", "graphql_introspection_exposed",
            "xml_injection_detected", "parameter_pollution_detected",
            "css_injection_in_style_tag",
        )):
            return "medium"
        if any(r in reasons for r in (
            "text_injection_reflected", "log_injection_detected",
            "redos_timeout_possible", "pdf_structure_leaked",
            "null_byte_bypass_possible", "unicode_bypass_possible",
            "prompt_injection_confirmed",
        )):
            return "low"
        return base

    def _determine_confidence(self, result: InjectionResult) -> str:
        if not result.anomaly_reasons:
            return "info"

        reason_count = len(result.anomaly_reasons)

        # High confidence: explicit, family-specific, verifiable evidence
        high_evidence = {
            "sql_error_disclosure", "command_execution_evidence",
            "template_injection_reflection", "xxe_file_content",
            "nosql_operator_detected", "nosql_auth_bypass_possible",
            "ldap_error_disclosure", "ldap_auth_bypass",
            "html_injection_rendered", "prompt_injection_confirmed",
            "prototype_pollution_confirmed", "ssi_injection_detected",
            "ssi_echo_executed", "pdf_structure_leaked", "dom_xss_dataflow",
            "xss_reflection", "el_evaluation_detected",
            "code_injection_eval_detected", "object_injection_detected",
            "path_traversal_file_content", "ssrf_response_content",
            "ssrf_redirect_detected", "open_redirect_confirmed",
            "xpath_error_disclosure", "xpath_auth_bypass",
            "graphql_introspection_exposed", "xml_injection_detected",
            "email_header_injection_detected", "header_injection_detected",
            "formula_injection_detected", "css_injection_in_style_tag",
        }

        # Medium confidence: timing / differential / indirect evidence
        medium_evidence = {
            "blind_sqli_time_delay_confirmed", "blind_sqli_boolean_confirmed",
            "sqli_boolean_status_diff", "blind_cmdi_time_delay_confirmed",
            "redos_timeout_possible", "code_injection_time_delay",
            "object_injection_time_delay", "null_byte_bypass_possible",
            "unicode_bypass_possible", "crlf_header_injection",
            "crlf_header_split", "parameter_pollution_detected",
            "open_redirect_body_leak",
        }

        if any(r in high_evidence for r in result.anomaly_reasons):
            return "high"
        if any(r in medium_evidence for r in result.anomaly_reasons):
            return "medium"
        if reason_count >= 3:
            return "medium"
        return "low"

    def _generate_description(self, result: InjectionResult) -> str:
        family_desc = {
            "sqli": "SQL Injection", "xss": "Cross-Site Scripting", "cmdi": "Command Injection",
            "ssti": "Server-Side Template Injection", "xxe": "XML External Entity",
            "ssrf": "Server-Side Request Forgery", "nosql": "NoSQL Injection",
            "xpath": "XPath Injection", "path_traversal": "Path Traversal",
            "open_redirect": "Open Redirect", "crlf": "CRLF Injection",
            "header_injection": "Header Injection", "email_injection": "Email Header Injection",
            "code_injection": "Code Injection", "formula_injection": "CSV/Formula Injection",
            "htmli": "HTML Injection", "texti": "Text Injection",
            "ldapi": "LDAP Injection",
        }
        desc = family_desc.get(result.family, "Security vulnerability")
        reasons = ", ".join(result.anomaly_reasons)
        return (
            f"{desc} via {result.subtype} ({result.mutation}). "
            f"Anomaly indicators: {reasons}. Payload: {result.payload_string[:200]}"
        )

    def cancel(self):
        self._cancelled = True

    def get_stats(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "requests_sent": self._requests_sent,
            "findings_count": self._findings_count,
            "total_tasks": self._total_tasks,
            "completed_tasks": self._completed_tasks,
            "cancelled": self._cancelled,
        }
