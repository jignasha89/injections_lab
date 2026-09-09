import asyncio
import json
import logging
import os
import time
from typing import Optional

from backend.api.websocket import emit_tool_output, emit_finding
from backend.config import settings
from backend.engine.tools.base_adapter import BaseAdapter

logger = logging.getLogger(__name__)

NUCLEI_DEFAULT_TAGS = [
    "sqli", "xss", "rce", "lfi", "ssrf", "xxe",
    "path-traversal", "crlf", "oast", "redirect",
    "headers", "prototype-pollution", "log4shell",
    "ssti", "graphql", "takeover",
]
NUCLEI_DEFAULT_SEVERITIES = ["critical", "high", "medium"]


class NucleiAdapter(BaseAdapter):
    """Nuclei vulnerability scanner integration adapter."""

    def __init__(self):
        super().__init__()
        self._template_index = 0

    async def start_scan(self, target: str, config: dict) -> str:
        """Start a Nuclei scan."""
        session_id = config.get("scan_id", f"nuclei_{int(time.time())}")
        self._running[session_id] = True
        self._results[session_id] = []
        self._progress[session_id] = 0.0

        task = asyncio.create_task(self._run_nuclei(session_id, target, config))
        self._tasks[session_id] = task
        return session_id

    async def _run_nuclei(
        self, session_id: str, target: str, config: dict
    ) -> None:
        """Build and execute the nuclei command."""
        try:
            tags = config.get("tags", NUCLEI_DEFAULT_TAGS)
            severities = config.get("severities", NUCLEI_DEFAULT_SEVERITIES)
            template_paths = config.get("template_paths", "")
            exclude_tags = config.get("exclude_tags", [])
            rate_limit = config.get("rate_limit", settings.RATE_LIMIT_DEFAULT)
            concurrency = config.get("concurrency", settings.CONCURRENCY_DEFAULT)
            timeout = config.get("timeout", 300)
            proxy = config.get("proxy", "")
            custom_headers = config.get("custom_headers", {})
            templates_only = config.get("templates_only", False)
            skip_ssl = config.get("skip_ssl", True)
            auto_update = config.get("auto_update", False)
            output_dir = config.get("output_dir", "")

            cmd = [settings.NUCLEI_PATH, "-u", target]

            cmd.extend(["-json"])

            if tags:
                cmd.extend(["-tags", ",".join(tags)])

            if severities:
                cmd.extend(["-severity", ",".join(severities)])

            if template_paths:
                for tp in template_paths.split(","):
                    tp = tp.strip()
                    if tp:
                        cmd.extend(["-t", tp])

            if exclude_tags:
                cmd.extend(["-exclude-tags", ",".join(exclude_tags)])

            cmd.extend(["-rl", str(rate_limit)])
            cmd.extend(["-c", str(concurrency)])
            cmd.extend(["-timeout", str(timeout)])

            if proxy:
                cmd.extend(["-proxy", proxy])

            if custom_headers:
                for key, value in custom_headers.items():
                    cmd.extend(["-H", f"{key}: {value}"])

            if templates_only:
                cmd.append("-templates-only")

            if skip_ssl:
                cmd.append("-skip-ssl")

            if auto_update:
                cmd.append("-update-templates")

            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                cmd.extend(["-o", os.path.join(output_dir, f"nuclei_{session_id}.jsonl")])

            await emit_tool_output(
                session_id, "nuclei",
                f"Running: {' '.join(cmd)}",
            )

            process = await self._spawn_process(session_id, cmd)
            await self._stream_output(
                session_id, process, "nuclei",
                parse_callback=self._parse_json_line,
            )
            await process.wait()

            exit_code = process.returncode
            if exit_code == 0:
                self._progress[session_id] = 100.0
                await emit_tool_output(
                    session_id, "nuclei",
                    f"Nuclei scan complete. Found {len(self._results[session_id])} findings.",
                )
            elif exit_code is not None and exit_code > 0:
                await emit_tool_output(
                    session_id, "nuclei",
                    f"Nuclei exited with code {exit_code}.",
                )
            else:
                await emit_tool_output(
                    session_id, "nuclei", "Nuclei process terminated.",
                )
        except asyncio.CancelledError:
            await emit_tool_output(session_id, "nuclei", "Scan cancelled")
        except Exception as e:
            logger.error(f"Nuclei scan error: {e}")
            await emit_tool_output(
                session_id, "nuclei", f"Scan error: {str(e)}"
            )
        finally:
            self._running[session_id] = False

    def _parse_json_line(self, line: str, session_id: str) -> None:
        """Parse a single JSON output line from nuclei."""
        if not line.strip():
            return

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return

        if "template-id" in data or "info" in data:
            finding = self._convert_to_finding(data, session_id)
            if finding:
                self._results[session_id].append(finding)
                loop = asyncio.get_event_loop()
                loop.create_task(emit_finding(session_id, finding))

            template_id = data.get("template-id", "unknown")
            severity = data.get("info", {}).get("severity", "info")
            matched_at = data.get("matched-at", data.get("host", ""))

            loop = asyncio.get_event_loop()
            loop.create_task(
                emit_tool_output(
                    session_id, "nuclei",
                    f"[{severity.upper()}] {template_id} - {matched_at}",
                )
            )

    def _convert_to_finding(self, data: dict, session_id: str) -> Optional[dict]:
        """Convert a nuclei JSON result to a Finding dict."""
        info = data.get("info", {})
        template_id = data.get("template-id", "unknown")
        matched_at = data.get("matched-at", data.get("host", ""))
        severity = info.get("severity", "info")
        classification = data.get("classification", {})
        curl_command = data.get("curl-command", "")
        matcher_name = data.get("matcher-name", "")
        extracted = data.get("extracted-results", [])
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        cvss_score = 0.0
        cvss_vector = ""
        if "cvss-metrics" in classification:
            cvss_vector = classification.get("cvss-metrics", "")
        if "cvss-score" in classification:
            try:
                cvss_score = float(classification["cvss-score"])
            except (ValueError, TypeError):
                cvss_score = 0.0

        cwe = classification.get("cwe-id", "")
        if isinstance(cwe, list):
            cwe = ", ".join(cwe)

        vulnerability_id = ""
        for vid_key in ["cve-id", "cve", "ghsa-id"]:
            val = classification.get(vid_key, "")
            if val:
                if isinstance(val, list):
                    vulnerability_id = ", ".join(val)
                else:
                    vulnerability_id = str(val)
                break

        references = info.get("reference", [])
        if isinstance(references, str):
            references = [r.strip() for r in references.split("\n") if r.strip()]

        injection_family = "nuclei_finding"
        injection_subtype = template_id
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in ("sqli", "sql-injection"):
                injection_family = "sqli"
                injection_subtype = "nuclei_sqli"
                break
            elif tag_lower in ("xss", "cross-site-scripting"):
                injection_family = "xss"
                injection_subtype = "nuclei_xss"
                break
            elif tag_lower in ("rce", "remote-code-execution"):
                injection_family = "cmdi"
                injection_subtype = "nuclei_rce"
                break
            elif tag_lower in ("lfi", "local-file-inclusion", "path-traversal"):
                injection_family = "path_traversal"
                injection_subtype = "nuclei_lfi"
                break
            elif tag_lower in ("ssrf",):
                injection_family = "ssrf"
                injection_subtype = "nuclei_ssrf"
                break
            elif tag_lower in ("xxe", "xml-external-entity"):
                injection_family = "xxe"
                injection_subtype = "nuclei_xxe"
                break
            elif tag_lower in ("ssti", "server-side-template-injection"):
                injection_family = "ssti"
                injection_subtype = "nuclei_ssti"
                break
            elif tag_lower in ("crlf", "crlf-injection"):
                injection_family = "crlf"
                injection_subtype = "nuclei_crlf"
                break
            elif tag_lower in ("takeover",):
                injection_family = "subdomain_takeover"
                injection_subtype = "nuclei_takeover"
                break
            elif tag_lower in ("log4shell",):
                injection_family = "rce"
                injection_subtype = "nuclei_log4shell"
                break

        return {
            "title": f"Nuclei: {info.get('name', template_id)}",
            "description": info.get(
                "description",
                f"Nuclei template {template_id} matched at {matched_at}",
            ),
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "confidence": "high",
            "vulnerability_id": vulnerability_id,
            "cwe_id": f"CWE-{cwe}" if cwe and not str(cwe).startswith("CWE-") else cwe,
            "injection_family": injection_family,
            "injection_subtype": injection_subtype,
            "affected_url": matched_at,
            "affected_parameter": matcher_name,
            "payload": curl_command,
            "request_data": {
                "template_id": template_id,
                "matched_at": matched_at,
                "matcher_name": matcher_name,
                "curl_command": curl_command,
                "type": data.get("type", ""),
                "tags": tags,
            },
            "response_data": {
                "matcher_name": matcher_name,
                "extracted_results": extracted,
                "type": data.get("type", ""),
                "status": data.get("status", ""),
                "ip": data.get("ip", ""),
                "timestamp": data.get("timestamp", ""),
                "curl_command": curl_command,
            },
            "evidence_json": {
                "nuclei_template": template_id,
                "nuclei_info": info,
                "nuclei_classification": classification,
                "nuclei_tags": tags,
                "matcher_name": matcher_name,
                "extracted_results": extracted,
                "curl_command": curl_command,
            },
            "mitigation_text": info.get("remediation", ""),
            "references_json": references,
        }

    async def get_results(self, session_id: str) -> list:
        """Return accumulated findings."""
        return self._results.get(session_id, [])
