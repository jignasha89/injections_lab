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

ZAP_API_BASE = "http://127.0.0.1:{port}/JSON"
ZAP_API_HTML = "http://127.0.0.1:{port}"
ZAP_DEFAULT_PORT = 8080
ZAP_STARTUP_TIMEOUT = 30
ZAP_POLL_INTERVAL = 2


class ZAPAdapter(BaseAdapter):
    """OWASP ZAP integration adapter."""

    def __init__(self, port: int = ZAP_DEFAULT_PORT):
        super().__init__()
        self.port = port
        self._api_base = ZAP_API_BASE.format(port=self.port)
        self._api_html = ZAP_API_HTML.format(port=self.port)
        self._http_client: Optional[httpx.AsyncClient] = None
        self._context_ids: dict[str, str] = {}
        self._scan_ids: dict[str, dict] = {}

    async def initialize(self) -> None:
        """Verify ZAP is accessible or start it."""
        self._http_client = httpx.AsyncClient(timeout=30.0)
        try:
            resp = await self._http_client.get(
                f"{self._api_base}/core/view/version/"
            )
            if resp.status_code == 200:
                data = resp.json()
                version = data.get("version", "unknown")
                logger.info(f"ZAP already running, version: {version}")
                return
        except (httpx.ConnectError, httpx.TimeoutException):
            pass

        await self._start_zap_subprocess()
        await self._wait_for_zap_ready()

    async def _start_zap_subprocess(self) -> None:
        """Start ZAP as a headless subprocess."""
        zap_path = settings.ZAP_PATH
        cmd = [
            zap_path,
            "-daemon",
            "-host", "127.0.0.1",
            "-port", str(self.port),
            "-config", "api.disablekey=true",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
            "-config", "connection.timeoutInSecs=120",
        ]

        env = {
            "JAVA_HOME": os.environ.get("JAVA_HOME", ""),
            "PATH": os.environ.get("PATH", ""),
        }

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **env},
        )
        self._processes["zap_main"] = process
        logger.info(f"Started ZAP subprocess on port {self.port}")

    async def _wait_for_zap_ready(self) -> None:
        """Wait for ZAP API to become available."""
        start = time.time()
        while time.time() - start < ZAP_STARTUP_TIMEOUT:
            try:
                resp = await self._http_client.get(
                    f"{self._api_base}/core/view/version/"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    logger.info(
                        f"ZAP ready, version: {data.get('version', 'unknown')}"
                    )
                    return
            except (httpx.ConnectError, httpx.TimeoutException):
                pass
            await asyncio.sleep(1)

        raise TimeoutError(
            f"ZAP did not start within {ZAP_STARTUP_TIMEOUT} seconds"
        )

    async def _api_call(
        self, endpoint: str, params: Optional[dict] = None
    ) -> dict:
        """Make a call to the ZAP API."""
        url = f"{self._api_base}/{endpoint}"
        try:
            resp = await self._http_client.get(url, params=params or {})
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"ZAP API call failed: {url} - {e}")
            return {}

    async def start_scan(self, target: str, config: dict) -> str:
        """Start a full ZAP scan against the target."""
        session_id = config.get("scan_id", f"zap_{int(time.time())}")
        self._running[session_id] = True
        self._results[session_id] = []
        self._progress[session_id] = 0.0
        self._scan_ids[session_id] = {}

        task = asyncio.create_task(self._run_scan_pipeline(session_id, target, config))
        self._tasks[session_id] = task
        return session_id

    async def _run_scan_pipeline(
        self, session_id: str, target: str, config: dict
    ) -> None:
        """Execute the full ZAP scan pipeline."""
        try:
            include_patterns = config.get("include_patterns", [f"^{target}.*"])
            exclude_patterns = config.get("exclude_patterns", [
                r"\.(css|js|png|jpg|gif|svg|ico|woff|woff2|ttf|eot)$",
            ])
            max_depth = config.get("max_depth", settings.MAX_DEPTH_DEFAULT)
            max_children = config.get("max_children", 0)

            context_id = await self._create_context(session_id, target)
            if not context_id:
                await emit_tool_output(
                    session_id, "zap",
                    "Failed to create ZAP context, using default context 0",
                )
                context_id = "0"

            await self._set_include_exclude(
                session_id, context_id, include_patterns, exclude_patterns
            )

            await emit_tool_output(
                session_id, "zap", f"Starting spider scan on {target}"
            )
            spider_scan_id = await self._start_spider(
                session_id, target, context_id, max_depth
            )
            if spider_scan_id:
                await self._poll_spider_status(session_id, spider_scan_id)

            await emit_tool_output(
                session_id, "zap", "Starting AJAX spider"
            )
            ajax_scan_id = await self._start_ajax_spider(
                session_id, context_id
            )
            if ajax_scan_id:
                await self._poll_ajax_spider_status(session_id, ajax_scan_id)

            await emit_tool_output(
                session_id, "zap", "Starting active scan"
            )
            active_scan_id = await self._start_active_scan(
                session_id, target, context_id, max_children
            )
            if active_scan_id:
                await self._poll_active_scan_status(session_id, active_scan_id)

            await self._collect_alerts(session_id, context_id)
            self._progress[session_id] = 100.0

            await emit_tool_output(
                session_id, "zap",
                f"ZAP scan complete. Found {len(self._results[session_id])} alerts.",
            )
        except asyncio.CancelledError:
            await emit_tool_output(session_id, "zap", "Scan cancelled")
        except Exception as e:
            logger.error(f"ZAP scan pipeline error: {e}")
            await emit_tool_output(session_id, "zap", f"Scan error: {str(e)}")
        finally:
            self._running[session_id] = False

    async def _create_context(
        self, session_id: str, target: str
    ) -> Optional[str]:
        """Create a ZAP context for the scan."""
        result = await self._api_call(
            "context/action/newContext/",
            {"contextName": f"ig_{session_id}"},
        )
        context_id = result.get("contextId")
        if context_id:
            self._context_ids[session_id] = context_id
            await self._api_call(
                "context/action/includeInContext/",
                {
                    "contextName": f"ig_{session_id}",
                    "regex": f"^{target.replace('://', '://([a-zA-Z0-9._-]*\\.)*')}.*",
                },
            )
        return context_id

    async def _set_include_exclude(
        self,
        session_id: str,
        context_id: str,
        include_patterns: list[str],
        exclude_patterns: list[str],
    ) -> None:
        """Set include and exclude URL patterns for the context."""
        context_name = f"ig_{session_id}"
        for pattern in include_patterns:
            await self._api_call(
                "context/action/includeInContext/",
                {"contextName": context_name, "regex": pattern},
            )
        for pattern in exclude_patterns:
            await self._api_call(
                "context/action/excludeFromContext/",
                {"contextName": context_name, "regex": pattern},
            )

    async def _start_spider(
        self,
        session_id: str,
        target: str,
        context_id: str,
        max_depth: int,
    ) -> Optional[str]:
        """Start the ZAP spider."""
        result = await self._api_call(
            "spider/action/scan/",
            {
                "url": target,
                "maxChildren": "0",
                "recurse": "true",
                "contextName": f"ig_{session_id}",
                "subtreeOnly": "false",
            },
        )
        scan_id = result.get("scan")
        return scan_id

    async def _poll_spider_status(
        self, session_id: str, scan_id: str
    ) -> None:
        """Poll spider status until complete."""
        while self._running.get(session_id, False):
            result = await self._api_call(
                "spider/view/status/", {"scanId": scan_id}
            )
            progress_str = result.get("status", "0")
            try:
                progress = float(progress_str)
            except (ValueError, TypeError):
                progress = 0.0
            self._progress[session_id] = progress * 0.3
            await emit_tool_output(
                session_id, "zap",
                f"Spider progress: {progress}%",
            )
            if progress >= 100:
                break
            await asyncio.sleep(ZAP_POLL_INTERVAL)

    async def _start_ajax_spider(
        self, session_id: str, context_id: str
    ) -> Optional[str]:
        """Start the ZAP AJAX spider."""
        await self._api_call(
            "ajaxSpider/action/enable/",
        )
        result = await self._api_call(
            "ajaxSpider/action/scan/",
            {
                "url": "",
                "inScope": "true",
                "contextName": f"ig_{session_id}",
                "subtreeOnly": "false",
            },
        )
        return "ajax"

    async def _poll_ajax_spider_status(
        self, session_id: str, scan_id: str
    ) -> None:
        """Poll AJAX spider status until complete."""
        while self._running.get(session_id, False):
            result = await self._api_call("ajaxSpider/view/status/")
            status = result.get("status", "stopped")
            if status.lower() == "running":
                self._progress[session_id] = 30.0
                await emit_tool_output(
                    session_id, "zap", "AJAX spider running..."
                )
            elif status.lower() in ("stopped", "error"):
                break
            await asyncio.sleep(ZAP_POLL_INTERVAL * 2)

    async def _start_active_scan(
        self,
        session_id: str,
        target: str,
        context_id: str,
        max_children: int,
    ) -> Optional[str]:
        """Start the ZAP active scan."""
        result = await self._api_call(
            "ascan/action/scan/",
            {
                "url": target,
                "recurse": "true",
                "inScopeOnly": "false",
                "scanPolicyName": "",
                "children": str(max_children),
                "contextId": context_id,
            },
        )
        scan_id = result.get("scan")
        return scan_id

    async def _poll_active_scan_status(
        self, session_id: str, scan_id: str
    ) -> None:
        """Poll active scan status until complete."""
        while self._running.get(session_id, False):
            result = await self._api_call(
                "ascan/view/status/", {"scanId": scan_id}
            )
            progress_str = result.get("status", "0")
            try:
                progress = float(progress_str)
            except (ValueError, TypeError):
                progress = 0.0
            self._progress[session_id] = 30.0 + (progress * 0.6)
            await emit_tool_output(
                session_id, "zap",
                f"Active scan progress: {progress}%",
            )
            if progress >= 100:
                break
            await asyncio.sleep(ZAP_POLL_INTERVAL)

    async def _collect_alerts(
        self, session_id: str, context_id: str
    ) -> None:
        """Collect all alerts from ZAP and convert to findings."""
        result = await self._api_call(
            "alert/view/alerts/",
            {"baseurl": "", "start": "0", "count": "500"},
        )
        alerts = result.get("alerts", [])

        for alert in alerts:
            finding = self._convert_alert_to_finding(alert, session_id)
            self._results[session_id].append(finding)
            await emit_finding(session_id, finding)
            await emit_tool_output(
                session_id, "zap",
                f"[{alert.get('risk', 'info').upper()}] {alert.get('name', 'Unknown alert')}",
            )

        all_alerts = await self._api_call("alert/view/alertsSummary/", {"baseurl": ""})
        total = all_alerts.get("count", len(alerts))
        await emit_tool_output(
            session_id, "zap",
            f"Collected {total} total alerts from ZAP",
        )

    def _convert_alert_to_finding(self, alert: dict, session_id: str) -> dict:
        """Convert a ZAP alert to a Finding object."""
        risk = str(alert.get("risk", "Informational")).lower()
        risk_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
            "info": "info",
        }
        severity = risk_map.get(risk, "info")

        confidence_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "3": "high",
            "2": "medium",
            "1": "low",
        }
        confidence_val = alert.get("confidence", "Low")
        confidence = confidence_map.get(
            str(confidence_val).lower(),
            confidence_map.get(confidence_val, "low"),
        )

        cwe_id = alert.get("cweid", "")
        wascid = alert.get("wascid", "")
        plugin_id = alert.get("pluginId", "")

        return {
            "title": alert.get("name", "ZAP Alert"),
            "description": alert.get("desc", ""),
            "severity": severity,
            "cvss_score": float(alert.get("risk", 0)) * 3.3,
            "cvss_vector": alert.get("cve", ""),
            "confidence": confidence,
            "vulnerability_id": f"ZAP-{plugin_id}" if plugin_id else "",
            "cwe_id": f"CWE-{cwe_id}" if cwe_id else "",
            "injection_family": "zap_finding",
            "injection_subtype": alert.get("pluginId", ""),
            "affected_url": alert.get("url", ""),
            "affected_parameter": alert.get("param", ""),
            "payload": alert.get("attack", ""),
            "request_data": {
                "method": alert.get("method", ""),
                "url": alert.get("url", ""),
                "param": alert.get("param", ""),
                "attack": alert.get("attack", ""),
            },
            "response_data": {
                "status_code": alert.get("code", 0),
                "evidence": alert.get("evidence", ""),
                "message": alert.get("message", ""),
            },
            "evidence_json": {
                "zap_alert_ref": alert.get("alertRef", ""),
                "plugin_id": plugin_id,
                "cwe_id": cwe_id,
                "wasc_id": wascid,
                "source_id": alert.get("sourceId", ""),
                "history_id": alert.get("historyId", ""),
                "method": alert.get("method", ""),
                "tags": alert.get("tags", {}),
            },
            "mitigation_text": alert.get("solution", ""),
            "references_json": [
                link for link in alert.get("reference", "").split("\n") if link.strip()
            ],
        }

    async def get_results(self, session_id: str) -> list:
        """Return findings for the given session."""
        return self._results.get(session_id, [])

    async def stop_scan(self, session_id: str) -> bool:
        """Stop the ZAP scan."""
        await self._api_call("spider/action/stop/", {"scanId": "0"})
        await self._api_call("ascan/action/stop/", {"scanId": "0"})
        await self._api_call("ajaxSpider/action/stop/")
        return await super().stop_scan(session_id)

    async def cleanup(self) -> None:
        """Stop all ZAP processes and close HTTP client."""
        await super().cleanup()
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
        zap_proc = self._processes.pop("zap_main", None)
        if zap_proc and zap_proc.returncode is None:
            try:
                zap_proc.kill()
                await zap_proc.wait()
            except ProcessLookupError:
                pass
