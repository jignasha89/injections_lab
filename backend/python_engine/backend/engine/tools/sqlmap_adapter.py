import asyncio
import json
import logging
import os
import signal
import time
from typing import Optional

import httpx

from backend.api.websocket import emit_tool_output, emit_finding
from backend.config import settings
from backend.engine.tools.base_adapter import BaseAdapter

logger = logging.getLogger(__name__)

SQLMAP_API_BASE = "http://127.0.0.1:{port}"
SQLMAP_API_PORT = 8775
SQLMAP_STARTUP_TIMEOUT = 30
SQLMAP_POLL_INTERVAL = 3


class SQLMapAdapter(BaseAdapter):
    """SQLMap API integration adapter."""

    def __init__(self, port: int = SQLMAP_API_PORT):
        super().__init__()
        self.port = port
        self._api_base = SQLMAP_API_BASE.format(port=self.port)
        self._http_client: Optional[httpx.AsyncClient] = None
        self._task_ids: dict[str, str] = {}

    async def initialize(self) -> None:
        """Start sqlmapapi.py server if not already running."""
        self._http_client = httpx.AsyncClient(timeout=60.0)
        try:
            resp = await self._http_client.get(f"{self._api_base}/task/new")
            if resp.status_code == 200:
                logger.info("sqlmap API server already running")
                return
        except (httpx.ConnectError, httpx.TimeoutException):
            pass

        await self._start_sqlmap_server()
        await self._wait_for_server_ready()

    async def _start_sqlmap_server(self) -> None:
        """Start the sqlmap API server."""
        sqlmap_path = settings.SQLMAP_PATH
        cmd = [
            "python", sqlmap_path, "--api",
            "--port", str(self.port),
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._processes["sqlmap_server"] = process
        logger.info(f"Started sqlmap API server on port {self.port}")

    async def _wait_for_server_ready(self) -> None:
        """Wait for sqlmap API to become available."""
        start = time.time()
        while time.time() - start < SQLMAP_STARTUP_TIMEOUT:
            try:
                resp = await self._http_client.get(
                    f"{self._api_base}/task/new"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("success"):
                        logger.info("sqlmap API server ready")
                        return
            except (httpx.ConnectError, httpx.TimeoutException):
                pass
            await asyncio.sleep(1)

        raise TimeoutError(
            f"sqlmap API server did not start within {SQLMAP_STARTUP_TIMEOUT}s"
        )

    async def _api_call(
        self,
        method: str,
        endpoint: str,
        data: Optional[dict] = None,
    ) -> dict:
        """Make an HTTP call to the sqlmap API."""
        url = f"{self._api_base}{endpoint}"
        try:
            if method == "POST":
                resp = await self._http_client.post(url, data=data or {})
            else:
                resp = await self._http_client.get(url, params=data or {})
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"sqlmap API call failed: {method} {url} - {e}")
            return {}

    async def start_scan(self, target: str, config: dict) -> str:
        """Start a sqlmap scan."""
        session_id = config.get("scan_id", f"sqlmap_{int(time.time())}")
        self._running[session_id] = True
        self._results[session_id] = []
        self._progress[session_id] = 0.0

        task = asyncio.create_task(self._run_scan(session_id, target, config))
        self._tasks[session_id] = task
        return session_id

    async def _run_scan(
        self, session_id: str, target: str, config: dict
    ) -> None:
        """Execute the sqlmap scan pipeline."""
        try:
            result = await self._api_call("POST", "/task/new")
            taskid = result.get("taskid")
            if not taskid:
                await emit_tool_output(
                    session_id, "sqlmap", "Failed to create sqlmap task"
                )
                return

            self._task_ids[session_id] = taskid
            await emit_tool_output(
                session_id, "sqlmap",
                f"Created sqlmap task: {taskid}",
            )

            url = config.get("url", target)
            data = config.get("data", "")
            method = config.get("method", "GET").upper()
            headers = config.get("headers", {})
            cookie = config.get("cookie", "")
            level = config.get("level", 5)
            risk = config.get("risk", 3)
            techniques = config.get("techniques", "BEUSTQ")
            tamper = config.get("tamper", "")
            dbms = config.get("dbms", "")
            os_name = config.get("os", "")
            thread_count = config.get("threads", 4)
            timeout = config.get("timeout", 30)
            retries = config.get("retries", 3)
            proxy = config.get("proxy", "")
            batch = config.get("batch", True)
            forms = config.get("forms", False)
            crawl_depth = config.get("crawl_depth", 0)

            await emit_tool_output(
                session_id, "sqlmap",
                f"Configuring scan options for {url}",
            )

            options_payload = {
                "url": url,
                "level": str(level),
                "risk": str(risk),
                "techniques": techniques,
                "threads": str(thread_count),
                "timeout": str(timeout),
                "retries": str(retries),
            }

            if data:
                options_payload["data"] = data
                options_payload["method"] = method

            if headers:
                header_str = "\n".join(
                    f"{k}: {v}" for k, v in headers.items()
                )
                options_payload["headers"] = header_str

            if cookie:
                options_payload["cookie"] = cookie

            if tamper:
                options_payload["tamper"] = tamper

            if dbms:
                options_payload["dbms"] = dbms

            if os_name:
                options_payload["os"] = os_name

            if proxy:
                options_payload["proxy"] = proxy

            options_payload["batch"] = "true" if batch else "false"

            if forms:
                options_payload["forms"] = "true"

            if crawl_depth > 0:
                options_payload["crawl"] = str(crawl_depth)

            opt_result = await self._api_call(
                "POST",
                f"/option/{taskid}/set",
                data=options_payload,
            )

            if not opt_result.get("success"):
                await emit_tool_output(
                    session_id, "sqlmap",
                    f"Failed to set options: {opt_result}",
                )
                return

            await emit_tool_output(
                session_id, "sqlmap",
                "Options configured. Starting scan...",
            )

            start_result = await self._api_call(
                "POST", f"/scan/{taskid}/start"
            )
            if not start_result.get("success"):
                await emit_tool_output(
                    session_id, "sqlmap",
                    f"Failed to start scan: {start_result}",
                )
                return

            await self._poll_scan_status(session_id, taskid)
            await self._collect_results(session_id, taskid)

            self._progress[session_id] = 100.0
            await emit_tool_output(
                session_id, "sqlmap",
                f"sqlmap scan complete. Found {len(self._results[session_id])} findings.",
            )
        except asyncio.CancelledError:
            await emit_tool_output(session_id, "sqlmap", "Scan cancelled")
        except Exception as e:
            logger.error(f"sqlmap scan error: {e}")
            await emit_tool_output(
                session_id, "sqlmap", f"Scan error: {str(e)}"
            )
        finally:
            self._running[session_id] = False

    async def _poll_scan_status(
        self, session_id: str, taskid: str
    ) -> None:
        """Poll sqlmap scan status until complete."""
        while self._running.get(session_id, False):
            status_result = await self._api_call(
                "GET", f"/scan/{taskid}/status"
            )
            status_data = status_result.get("status", 0)

            if status_data == -1:
                await emit_tool_output(
                    session_id, "sqlmap", "Scan status: not running"
                )
                break

            if status_data == 1:
                self._progress[session_id] = 50.0
                log_result = await self._api_call(
                    "GET", f"/scan/{taskid}/log"
                )
                logs = log_result.get("log", [])
                if logs:
                    latest = logs[-1] if logs else {}
                    log_msg = latest.get("message", "")
                    log_level = latest.get("level", "")
                    if log_msg:
                        await emit_tool_output(
                            session_id, "sqlmap",
                            f"[{log_level}] {log_msg}",
                        )

            elif status_data == 0:
                self._progress[session_id] = 100.0
                break

            await asyncio.sleep(SQLMAP_POLL_INTERVAL)

    async def _collect_results(
        self, session_id: str, taskid: str
    ) -> None:
        """Collect scan results and convert to findings."""
        data_result = await self._api_call(
            "GET", f"/scan/{taskid}/data"
        )
        data = data_result.get("data", [])

        if not data:
            await emit_tool_output(
                session_id, "sqlmap",
                "No SQL injection vulnerabilities found",
            )
            return

        for item in data:
            finding = self._convert_result_to_finding(item, session_id)
            if finding:
                self._results[session_id].append(finding)
                await emit_finding(session_id, finding)
                await emit_tool_output(
                    session_id, "sqlmap",
                    f"[CRITICAL] {finding['title']}",
                )

    def _convert_result_to_finding(
        self, item: dict, session_id: str
    ) -> Optional[dict]:
        """Convert a sqlmap result item to a Finding dict."""
        title = item.get("title", "SQL Injection")
        payload = item.get("payload", "")
        data_str = item.get("data", {})

        if isinstance(data_str, dict):
            detail = json.dumps(data_str, indent=2)
        else:
            detail = str(data_str)

        severity = "critical"
        if "boolean-based" in title.lower() or "time-based" in title.lower():
            severity = "high"
        elif "error-based" in title.lower():
            severity = "critical"
        elif "stacked" in title.lower():
            severity = "critical"
        elif "inline" in title.lower():
            severity = "critical"

        dbms = ""
        if isinstance(data_str, dict):
            dbms = data_str.get("dbms", "")
        if not dbms:
            for db in ["MySQL", "PostgreSQL", "Microsoft SQL Server", "Oracle", "SQLite"]:
                if db.lower() in title.lower():
                    dbms = db
                    break

        return {
            "title": f"SQL Injection - {title}",
            "description": (
                f"SQLMap detected SQL injection vulnerability. "
                f"{detail}"
            ),
            "severity": severity,
            "cvss_score": 9.8 if severity == "critical" else 8.6,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "confidence": "high",
            "vulnerability_id": "",
            "cwe_id": "CWE-89",
            "injection_family": "sqli",
            "injection_subtype": title.lower().replace(" ", "_").replace("-", "_"),
            "affected_url": item.get("url", ""),
            "affected_parameter": item.get("parameter", ""),
            "payload": payload,
            "request_data": {
                "url": item.get("url", ""),
                "parameter": item.get("parameter", ""),
                "title": title,
                "payload": payload,
            },
            "response_data": {
                "dbms": dbms,
                "detail": detail,
            },
            "evidence_json": {
                "sqlmap_title": title,
                "sqlmap_payload": payload,
                "sqlmap_data": data_str,
                "dbms": dbms,
            },
            "mitigation_text": (
                "Use parameterized queries/prepared statements. "
                "Implement proper input validation and escaping. "
                "Use stored procedures where appropriate."
            ),
            "references_json": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
        }

    async def get_results(self, session_id: str) -> list:
        """Return accumulated findings."""
        return self._results.get(session_id, [])

    async def cleanup(self) -> None:
        """Clean up sqlmap processes and resources."""
        await super().cleanup()
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
        server_proc = self._processes.pop("sqlmap_server", None)
        if server_proc and server_proc.returncode is None:
            try:
                server_proc.kill()
                await server_proc.wait()
            except ProcessLookupError:
                pass
