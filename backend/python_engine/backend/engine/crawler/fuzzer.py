import asyncio
import json
import logging
import os
import re
import tempfile
from pathlib import Path

from backend.config import settings

logger = logging.getLogger(__name__)

FFUF_OUTPUT_PATTERN = re.compile(
    r'"url"\s*:\s*"([^"]+)".*?"status"\s*:\s*(\d+).*?"length"\s*:\s*(\d+)',
    re.S,
)


class Fuzzer:
    def __init__(
        self,
        ffuf_path: str = "",
        concurrency: int = 40,
        rate_limit: int = 0,
        timeout: int = 60,
        extensions: str = "",
        wordlist: str = "",
    ):
        self.ffuf_path = ffuf_path or settings.FFUF_PATH
        self.concurrency = concurrency
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.extensions = extensions
        self.wordlist = wordlist or os.path.join(
            settings.SECLISTS_PATH, "Discovery", "Web-Content", "common.txt"
        )
        self.results: list[dict] = []

    async def run_directory_fuzz(
        self,
        target_url: str,
        scan_id: str = "",
        wordlist: str = "",
    ) -> dict:
        from backend.api.websocket import emit_scan_progress, emit_tool_output

        await emit_tool_output(scan_id, "fuzzer", f"Starting directory fuzzing on {target_url}")
        await emit_scan_progress(
            scan_id,
            {
                "phase": "fuzzing",
                "percentage": 60.0,
                "requests_sent": 0,
                "findings_count": 0,
                "current_tool": "ffuf_directory",
            },
        )

        wl = wordlist or self.wordlist
        output_file = os.path.join(tempfile.gettempdir(), f"ffuf_dir_{scan_id}.json")

        cmd = [
            self.ffuf_path,
            "-u", f"{target_url}/FUZZ",
            "-w", wl,
            "-mc", "200,201,204,301,302,307,401,403,405,500",
            "-of", "json",
            "-o", output_file,
            "-t", str(self.concurrency),
            "-timeout", str(self.timeout),
            "-noninteractive", "-s",
        ]

        if self.extensions:
            cmd.extend(["-e", self.extensions])

        if self.rate_limit > 0:
            cmd.extend(["-rate", str(self.rate_limit)])

        await emit_tool_output(scan_id, "fuzzer", "Initiating background fuzzing engine...")

        results = await self._run_ffuf(cmd, output_file, scan_id, "directory")
        self.results.extend(results)

        await emit_tool_output(scan_id, "fuzzer", f"Directory fuzzing complete, found {len(results)} results")

        return {
            "type": "directory",
            "target_url": target_url,
            "results": results,
            "total": len(results),
        }

    async def run_file_fuzz(
        self,
        target_url: str,
        scan_id: str = "",
        extensions: str = "php,html,js,txt,bak,old,conf,config,ini,log",
    ) -> dict:
        from backend.api.websocket import emit_scan_progress, emit_tool_output

        await emit_tool_output(scan_id, "fuzzer", f"Starting file fuzzing on {target_url}")
        await emit_scan_progress(
            scan_id,
            {
                "phase": "fuzzing",
                "percentage": 65.0,
                "requests_sent": 0,
                "findings_count": 0,
                "current_tool": "ffuf_file",
            },
        )

        file_wordlist = os.path.join(
            settings.SECLISTS_PATH, "Discovery", "Web-Content", "raft-small-files.txt"
        )
        if not os.path.exists(file_wordlist):
            file_wordlist = os.path.join(
                settings.SECLISTS_PATH, "Discovery", "Web-Content", "common.txt"
            )

        output_file = os.path.join(tempfile.gettempdir(), f"ffuf_file_{scan_id}.json")

        cmd = [
            self.ffuf_path,
            "-u", f"{target_url}/FUZZ",
            "-w", file_wordlist,
            "-mc", "200,201,204,301,302,307,401,403,500",
            "-of", "json",
            "-o", output_file,
            "-t", str(self.concurrency),
            "-timeout", str(self.timeout),
            "-noninteractive", "-s",
            "-e", extensions,
        ]

        await emit_tool_output(scan_id, "fuzzer", "Initiating background fuzzing engine...")

        results = await self._run_ffuf(cmd, output_file, scan_id, "file")
        self.results.extend(results)

        await emit_tool_output(scan_id, "fuzzer", f"File fuzzing complete, found {len(results)} results")

        return {
            "type": "file",
            "target_url": target_url,
            "results": results,
            "total": len(results),
        }

    async def run_parameter_fuzz(
        self,
        target_url: str,
        scan_id: str = "",
        method: str = "GET",
        wordlist: str = "",
    ) -> dict:
        from backend.api.websocket import emit_scan_progress, emit_tool_output

        await emit_tool_output(scan_id, "fuzzer", f"Starting parameter fuzzing on {target_url}")
        await emit_scan_progress(
            scan_id,
            {
                "phase": "fuzzing",
                "percentage": 70.0,
                "requests_sent": 0,
                "findings_count": 0,
                "current_tool": "ffuf_param",
            },
        )

        param_wordlist = wordlist or os.path.join(
            settings.SECLISTS_PATH, "Discovery", "Web-Content", "burp-parameter-names.txt"
        )
        if not os.path.exists(param_wordlist):
            param_wordlist = os.path.join(
                settings.SECLISTS_PATH, "Discovery", "Web-Content", "common.txt"
            )

        output_file = os.path.join(tempfile.gettempdir(), f"ffuf_param_{scan_id}.json")

        if "?" in target_url:
            fuzz_url = re.sub(r'=\w*', '=FUZZ', target_url)
            if "=" not in fuzz_url:
                fuzz_url = f"{target_url}&FUZZ=test"
        else:
            fuzz_url = f"{target_url}?FUZZ=test"

        cmd = [
            self.ffuf_path,
            "-u", fuzz_url,
            "-w", param_wordlist,
            "-mc", "200,201,204,301,302,307,401,403,500",
            "-of", "json",
            "-o", output_file,
            "-t", str(self.concurrency),
            "-timeout", str(self.timeout),
            "-noninteractive", "-s",
        ]

        if method.upper() == "POST":
            cmd.extend(["-X", "POST", "-d", "FUZZ=test"])

        await emit_tool_output(scan_id, "fuzzer", "Initiating background fuzzing engine...")

        results = await self._run_ffuf(cmd, output_file, scan_id, "parameter")
        self.results.extend(results)

        await emit_tool_output(scan_id, "fuzzer", f"Parameter fuzzing complete, found {len(results)} results")

        return {
            "type": "parameter",
            "target_url": target_url,
            "results": results,
            "total": len(results),
        }

    async def run_vhost_fuzz(
        self,
        target_url: str,
        scan_id: str = "",
        wordlist: str = "",
    ) -> dict:
        from backend.api.websocket import emit_scan_progress, emit_tool_output

        await emit_tool_output(scan_id, "fuzzer", f"Starting vhost fuzzing on {target_url}")
        await emit_scan_progress(
            scan_id,
            {
                "phase": "fuzzing",
                "percentage": 72.0,
                "requests_sent": 0,
                "findings_count": 0,
                "current_tool": "ffuf_vhost",
            },
        )

        vhost_wordlist = wordlist or os.path.join(
            settings.SECLISTS_PATH, "Discovery", "DNS", "subdomains-top1million-5000.txt"
        )
        if not os.path.exists(vhost_wordlist):
            vhost_wordlist = os.path.join(
                settings.SECLISTS_PATH, "Discovery", "Web-Content", "common.txt"
            )

        output_file = os.path.join(tempfile.gettempdir(), f"ffuf_vhost_{scan_id}.json")

        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        base_domain = parsed.netloc.split(":")[0]

        cmd = [
            self.ffuf_path,
            "-u", target_url,
            "-H", f"Host: FUZZ.{base_domain}",
            "-w", vhost_wordlist,
            "-mc", "200,201,204,301,302,307,401,403,500",
            "-of", "json",
            "-o", output_file,
            "-t", str(self.concurrency),
            "-timeout", str(self.timeout),
            "-noninteractive", "-s",
        ]

        await emit_tool_output(scan_id, "fuzzer", "Initiating background fuzzing engine...")

        results = await self._run_ffuf(cmd, output_file, scan_id, "vhost")
        self.results.extend(results)

        await emit_tool_output(scan_id, "fuzzer", f"Vhost fuzzing complete, found {len(results)} results")

        return {
            "type": "vhost",
            "target_url": target_url,
            "results": results,
            "total": len(results),
        }

    async def _run_ffuf(
        self,
        cmd: list[str],
        output_file: str,
        scan_id: str,
        fuzz_type: str,
    ) -> list[dict]:
        from backend.api.websocket import emit_tool_output

        parsed_results = []
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=self.timeout + 60
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                await emit_tool_output(scan_id, "fuzzer", f"Fuzzer {fuzz_type} timed out")
                return parsed_results
            except asyncio.CancelledError:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                raise

            if stdout:
                # We intentionally do not emit the raw fuzzer stdout lines 
                # to prevent cluttering the live engine logs with its logo 
                # and raw verbose outputs.
                pass

            if stderr:
                stderr_text = stderr.decode(errors="replace")
                if "error" in stderr_text.lower():
                    await emit_tool_output(scan_id, "fuzzer", f"Fuzzer error: {stderr_text[:500]}")

            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                parsed_results = self._parse_ffuf_output(content)

        except FileNotFoundError:
            await emit_tool_output(
                scan_id, "fuzzer",
                f"Fuzzer binary not found at {self.ffuf_path}. Install fuzzer or set FFUF_PATH."
            )
        except Exception as e:
            logger.error(f"Fuzzer execution error: {e}")
            await emit_tool_output(scan_id, "fuzzer", f"Error: {str(e)}")
        finally:
            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except OSError:
                    pass

        return parsed_results

    def _parse_ffuf_output(self, content: str) -> list[dict]:
        results = []
        try:
            data = json.loads(content)
            results_list = data.get("results", [])
            for item in results_list:
                results.append({
                    "url": item.get("url", ""),
                    "status": item.get("status", 0),
                    "length": item.get("length", 0),
                    "words": item.get("words", 0),
                    "lines": item.get("lines", 0),
                    "content_type": item.get("content-type", ""),
                    "redirectlocation": item.get("redirectlocation", ""),
                    "input": item.get("input", ""),
                    "duration": item.get("duration", 0),
                })
        except json.JSONDecodeError:
            results = self._parse_ffuf_text(content)
        return results

    def _parse_ffuf_text(self, content: str) -> list[dict]:
        results = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            match = FFUF_OUTPUT_PATTERN.search(line)
            if match:
                results.append({
                    "url": match.group(1),
                    "status": int(match.group(2)),
                    "length": int(match.group(3)),
                })
            else:
                parts = re.split(r'\s+', line)
                if len(parts) >= 3:
                    try:
                        status = int(parts[1])
                        length = int(parts[2])
                        results.append({
                            "url": parts[0],
                            "status": status,
                            "length": length,
                        })
                    except ValueError:
                        continue
        return results

    def get_all_results(self) -> list[dict]:
        return self.results
