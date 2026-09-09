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


class FuzzerAdapter(BaseAdapter):
    """Background fuzzing integration adapter."""

    FUZZ_MODES = {
        "directory": "-mc 200,301,302,403 -fc 404",
        "file": "-mc 200,301,302,403 -fc 404",
        "parameter": "-mc 200,301,302,403,500 -fc 404",
        "vhost": "-mc 200,301,302,403 -fc 404 -H 'Host: FUZZ.{target_host}'",
    }

    DEFAULT_WORDLISTS = {
        "directory": "common.txt",
        "file": "common.txt",
        "parameter": "burp-parameter-names.txt",
        "vhost": "subdomains-top1million-5000.txt",
    }

    def __init__(self):
        super().__init__()
        self._wordlist_base = settings.SECLISTS_PATH

    async def start_scan(self, target: str, config: dict) -> str:
        """Start an Background fuzzing scan."""
        session_id = config.get("scan_id", f"ffuf_{int(time.time())}")
        self._running[session_id] = True
        self._results[session_id] = []
        self._progress[session_id] = 0.0

        task = asyncio.create_task(self._run_ffuf(session_id, target, config))
        self._tasks[session_id] = task
        return session_id

    async def _run_ffuf(
        self, session_id: str, target: str, config: dict
    ) -> None:
        """Build and execute the fuzzer command."""
        try:
            fuzz_mode = config.get("fuzz_mode", "directory")
            wordlist = config.get("wordlist", "")
            threads = config.get("threads", settings.CONCURRENCY_DEFAULT)
            rate_limit = config.get("rate_limit", settings.RATE_LIMIT_DEFAULT)
            timeout = config.get("timeout", 30)
            extensions = config.get("extensions", "")
            filters = config.get("filters", "")
            matchers = config.get("matchers", "")
            headers = config.get("headers", {})
            data = config.get("data", "")
            method = config.get("method", "GET")
            recursion_depth = config.get("recursion_depth", 0)
            proxy = config.get("proxy", "")
            follow_redirects = config.get("follow_redirects", False)
            rate_limit_fuzzer = config.get("rate_limit_ffuf", 0)
            custom_args = config.get("custom_args", "")

            if not wordlist:
                wordlist = self._get_default_wordlist(fuzz_mode)

            if not os.path.isabs(wordlist):
                wordlist = os.path.join(self._wordlist_base, wordlist)

            if not os.path.isfile(wordlist):
                await emit_tool_output(
                    session_id, "fuzzer",
                    f"Wordlist not found: {wordlist}, creating minimal list",
                )
                wordlist = await self._create_fallback_wordlist(session_id, fuzz_mode)

            cmd = [settings.FFUF_PATH, "-u", target]

            cmd.extend(["-w", wordlist, "-o", "-", "-json"])

            mode_flags = self.FUZZ_MODES.get(fuzz_mode, self.FUZZ_MODES["directory"])
            cmd.extend(mode_flags.split())

            cmd.extend(["-s", "-t", str(threads)])
            if rate_limit_fuzzer > 0:
                cmd.extend(["-rate", str(rate_limit_ffuf)])

            if extensions:
                cmd.extend(["-e", extensions])

            if filters:
                cmd.extend(["-fc", filters])
            if matchers:
                cmd.extend(["-mc", matchers])

            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])

            if data:
                cmd.extend(["-d", data, "-X", method])

            if recursion_depth > 0:
                cmd.extend(["-recursion", "-recursion-depth", str(recursion_depth)])

            if proxy:
                cmd.extend(["-x", proxy])

            if follow_redirects:
                cmd.extend(["-fl", "0"])

            if custom_args:
                cmd.extend(custom_args.split())

            await emit_tool_output(
                session_id, "fuzzer",
                "Initiating background fuzzing engine...",
            )

            process = await self._spawn_process(session_id, cmd)
            await self._stream_output(
                session_id, process, "fuzzer",
                parse_callback=self._parse_json_line,
            )
            await process.wait()

            exit_code = process.returncode
            if exit_code == 0:
                self._progress[session_id] = 100.0
                await emit_tool_output(
                    session_id, "fuzzer",
                    f"fuzzer completed. Found {len(self._results[session_id])} results.",
                )
            elif exit_code is not None and exit_code > 0:
                await emit_tool_output(
                    session_id, "fuzzer",
                    f"fuzzer exited with code {exit_code}.",
                )
            else:
                await emit_tool_output(
                    session_id, "fuzzer", "fuzzer process terminated.",
                )
        except asyncio.CancelledError:
            if 'process' in locals() and process:
                try:
                    process.terminate()
                except Exception:
                    pass
            await emit_tool_output(session_id, "fuzzer", "Scan cancelled")
            raise
        except Exception as e:
            logger.error(f"fuzzer scan error: {e}")
            await emit_tool_output(session_id, "fuzzer", f"Scan error: {str(e)}")
        finally:
            self._running[session_id] = False

    def _get_default_wordlist(self, fuzz_mode: str) -> str:
        """Get the default wordlist path for a fuzz mode."""
        filename = self.DEFAULT_WORDLISTS.get(fuzz_mode, "common.txt")
        return os.path.join(
            self._wordlist_base, "Discovery", "Web-Content", filename
        )

    async def _create_fallback_wordlist(
        self, session_id: str, fuzz_mode: str
    ) -> str:
        """Create a minimal fallback wordlist if none exists."""
        fallback_dir = os.path.join(
            settings.BASE_DIR, "backend", "engine", "tools", "_fallback"
        )
        os.makedirs(fallback_dir, exist_ok=True)
        fallback_path = os.path.join(fallback_dir, f"ffuf_{fuzz_mode}.txt")

        entries = {
            "directory": [
                "admin", "login", "api", "backup", "config", "debug",
                "test", "dev", "staging", "uploads", "images", "css",
                "js", "static", "assets", "files", "docs", "help",
                "dashboard", "panel", "portal", "cgi-bin", ".env",
                ".git", ".svn", ".htaccess", "wp-admin", "wp-login.php",
                "robots.txt", "sitemap.xml", "crossdomain.xml",
                "server-status", "server-info", "phpinfo.php",
            ],
            "file": [
                "index.html", "index.php", "default.asp", "web.config",
                ".env", ".htaccess", "robots.txt", "sitemap.xml",
                "crossdomain.xml", "favicon.ico", "robots.txt",
                "readme.txt", "license.txt", "changelog.txt",
                "package.json", "composer.json", "Gemfile",
                "Dockerfile", "docker-compose.yml", ".gitignore",
            ],
            "parameter": [
                "id", "user", "admin", "debug", "test", "action",
                "cmd", "exec", "query", "search", "file", "path",
                "url", "redirect", "callback", "next", "return",
                "page", "lang", "token", "key", "api_key", "secret",
                "password", "passwd", "pass", "auth", "session",
            ],
            "vhost": [
                "www", "mail", "ftp", "admin", "api", "dev",
                "staging", "test", "beta", "app", "portal",
                "dashboard", "monitor", "grafana", "kibana",
                "jenkins", "gitlab", "jira", "confluence",
            ],
        }

        lines = entries.get(fuzz_mode, entries["directory"])
        with open(fallback_path, "w") as f:
            f.write("\n".join(lines) + "\n")

        await emit_tool_output(
            session_id, "fuzzer",
            f"Created fallback wordlist: {fallback_path}",
        )
        return fallback_path

    def _parse_json_line(self, line: str, session_id: str) -> None:
        """Parse a single JSON output line from ffuf."""
        if not line.strip():
            return

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return

        if "input" in data:
            result = data
            finding = self._convert_to_finding(result, session_id)
            if finding:
                self._results[session_id].append(finding)
                asyncio.get_event_loop().create_task(
                    emit_finding(session_id, finding)
                )

            fuzz_word = ""
            for v in result.get("input", {}).values():
                fuzz_word = v
                break
            status = result.get("status", 0)
            length = result.get("length", 0)
            words = result.get("words", 0)
            lines_count = result.get("lines", 0)
            url = result.get("url", "")

            asyncio.get_event_loop().create_task(
                emit_tool_output(
                    session_id, "fuzzer",
                    f"[{status}] {url} (words={words}, lines={lines_count}, len={length})",
                )
            )

    def _convert_to_finding(self, result: dict, session_id: str) -> Optional[dict]:
        """Convert an fuzzer result to a Finding dict."""
        status = result.get("status", 0)
        url = result.get("url", "")
        fuzz_word = ""
        for v in result.get("input", {}).values():
            fuzz_word = v
            break

        if status in (404, 0):
            return None

        severity = "info"
        title = f"fuzzer Discovery: {url}"

        if status == 200:
            severity = "info"
            title = f"Fuzzer: Accessible endpoint found - {url}"
        elif status in (301, 302):
            severity = "low"
            title = f"Fuzzer: Redirect found - {url}"
        elif status == 403:
            severity = "low"
            title = f"Fuzzer: Forbidden endpoint - {url}"
        elif status == 500:
            severity = "medium"
            title = f"Fuzzer: Server error on endpoint - {url}"

        return {
            "title": title,
            "description": (
                f"Background fuzzing discovered endpoint {url} returning HTTP {status}. "
                f"Fuzzed value: {fuzz_word}"
            ),
            "severity": severity,
            "cvss_score": 0.0,
            "cvss_vector": "",
            "confidence": "high",
            "vulnerability_id": "",
            "cwe_id": "",
            "injection_family": "ffuf_discovery",
            "injection_subtype": "endpoint_discovery",
            "affected_url": url,
            "affected_parameter": "",
            "payload": fuzz_word,
            "request_data": {
                "url": url,
                "status_code": status,
                "fuzz_word": fuzz_word,
            },
            "response_data": {
                "status_code": status,
                "content_length": result.get("length", 0),
                "words": result.get("words", 0),
                "lines": result.get("lines", 0),
                "content_type": result.get("content-type", ""),
                "redirectlocation": result.get("redirectlocation", ""),
            },
            "evidence_json": {
                "ffuf_result": result,
            },
        }

    async def get_results(self, session_id: str) -> list:
        """Return accumulated findings."""
        return self._results.get(session_id, [])
