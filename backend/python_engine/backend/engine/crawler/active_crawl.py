import asyncio
import json
import logging
import time
from typing import Any

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)

ZAP_API_BASE = "http://127.0.0.1:8090/JSON"
ZAP_API_CORE = ZAP_API_BASE + "/core"
ZAP_API_SPIDER = ZAP_API_BASE + "/spider"
ZAP_API_AJAX = ZAP_API_BASE + "/ajaxSpider"


class ActiveCrawl:
    def __init__(
        self,
        zap_port: int = 8090,
        zap_api_key: str = "",
        max_duration: int = 300,
    ):
        self.zap_port = zap_port
        self.zap_api_key = zap_api_key
        self.max_duration = max_duration
        self._zap_api_base = f"http://127.0.0.1:{zap_port}/JSON"
        self._zap_api_core = self._zap_api_base + "/core"
        self._zap_api_spider = self._zap_api_base + "/spider"
        self._zap_api_ajax = self._zap_api_base + "/ajaxSpider"
        self.discovered_urls: dict[str, dict] = {}
        self.discovered_forms: list[dict] = []
        self.spider_results: list[str] = []
        self.ajax_results: list[str] = []

    async def run(self, target_url: str, scan_id: str = "") -> dict:
        from backend.api.websocket import emit_scan_progress, emit_tool_output
        import os

        start_time = time.time()

        await emit_scan_progress(
            scan_id,
            {
                "phase": "active_crawl",
                "percentage": 35.0,
                "requests_sent": 0,
                "findings_count": 0,
                "current_tool": "zap_spider",
            },
        )

        # Don't burn seconds probing/starting ZAP when it isn't installed
        zap_installed = False # ZAP is optional and disabled to prevent hanging
        zap_alive = False
        if zap_installed:
            zap_alive = await self._check_zap_alive()
            if not zap_alive:
                await emit_tool_output(scan_id, "zap", "ZAP is not running, attempting to start...")
                started = await self._start_zap()
                if not started:
                    await emit_tool_output(scan_id, "zap", "Failed to start ZAP. Falling back to basic crawl.")
                    return await self._fallback_crawl(target_url, scan_id)
                await asyncio.sleep(5)
        else:
            pass

        if not zap_alive:
            return await self._fallback_crawl(target_url, scan_id)

        await emit_tool_output(scan_id, "zap", "ZAP is alive, starting spider...")

        await self._set_target(target_url)

        spider_id = await self._start_spider(target_url)
        if spider_id is not None:
            await emit_tool_output(scan_id, "zap", f"Spider started with ID: {spider_id}")
            await self._wait_for_spider(spider_id, scan_id)
            self.spider_results = await self._get_spider_results()
            await emit_tool_output(scan_id, "zap", f"Spider completed, found {len(self.spider_results)} URLs")
        else:
            await emit_tool_output(scan_id, "zap", "Failed to start spider")

        await emit_scan_progress(
            scan_id,
            {
                "phase": "active_crawl",
                "percentage": 50.0,
                "requests_sent": len(self.spider_results),
                "findings_count": 0,
                "current_tool": "zap_ajax_spider",
            },
        )

        ajax_started = await self._start_ajax_spider(target_url)
        if ajax_started:
            await emit_tool_output(scan_id, "zap", "AJAX spider started")
            await self._wait_for_ajax_spider(scan_id)
            self.ajax_results = await self._get_ajax_spider_results()
            await emit_tool_output(scan_id, "zap", f"AJAX spider completed, found {len(self.ajax_results)} URLs")
        else:
            await emit_tool_output(scan_id, "zap", "AJAX spider not available or failed to start")

        all_urls = set(self.spider_results + self.ajax_results)
        for url in all_urls:
            self.discovered_urls[url] = {
                "source": "zap",
                "spider": url in self.spider_results,
                "ajax_spider": url in self.ajax_results,
            }

        forms = await self._get_forms()
        self.discovered_forms = forms

        elapsed = time.time() - start_time
        await emit_tool_output(
            scan_id, "zap",
            f"Active crawl completed in {elapsed:.1f}s. "
            f"URLs: {len(all_urls)}, Forms: {len(forms)}"
        )

        return self._compile_results(target_url, elapsed)

    async def _check_zap_alive(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._zap_api_base}/core/view/version/")
                if resp.status_code == 200:
                    data = resp.json()
                    version = data.get("version", "unknown")
                    logger.info(f"ZAP is alive, version: {version}")
                    return True
        except Exception as e:
            logger.debug(f"ZAP check failed: {e}")
        return False

    async def _start_zap(self) -> bool:
        import subprocess
        zap_path = settings.ZAP_PATH
        try:
            cmd = [
                zap_path,
                "-daemon",
                "-port", str(self.zap_port),
                "-config", "api.disablekey=true",
                "-config", f"connection.timeoutInSecs={self.max_duration}",
            ]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info(f"Started ZAP with PID {process.pid}")
            for _ in range(30):
                await asyncio.sleep(2)
                if await self._check_zap_alive():
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to start ZAP: {e}")
            return False

    async def _set_target(self, target_url: str) -> None:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.get(
                    f"{self._zap_api_core}/accessUrl/",
                    params={"url": target_url, "followRedirects": "true"},
                )
        except Exception as e:
            logger.debug(f"Failed to set ZAP target: {e}")

    async def _start_spider(self, target_url: str) -> int | None:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._zap_api_spider}/scan/",
                    params={
                        "url": target_url,
                        "maxChildren": "0",
                        "recurse": "true",
                        " subtreeOnly": "false",
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("scan")
        except Exception as e:
            logger.error(f"Failed to start ZAP spider: {e}")
        return None

    async def _wait_for_spider(self, spider_id: int, scan_id: str) -> None:
        from backend.api.websocket import emit_tool_output
        start = time.time()
        while time.time() - start < self.max_duration:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(
                        f"{self._zap_api_spider}/status/",
                        params={"scanId": str(spider_id)},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        progress = int(data.get("status", "0"))
                        if progress >= 100:
                            await emit_tool_output(scan_id, "zap", f"Spider progress: 100%")
                            return
                        if progress % 20 == 0:
                            await emit_tool_output(scan_id, "zap", f"Spider progress: {progress}%")
            except Exception:
                pass
            await asyncio.sleep(3)

    async def _get_spider_results(self) -> list[str]:
        urls = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(f"{self._zap_api_spider}/results/")
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    for item in results:
                        url = item.get("url", "")
                        if url:
                            urls.append(url)
        except Exception as e:
            logger.error(f"Failed to get spider results: {e}")
        return urls

    async def _start_ajax_spider(self, target_url: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{self._zap_api_ajax}/scan/",
                    params={"url": target_url, "inScope": "true"},
                )
                return resp.status_code == 200
        except Exception as e:
            logger.debug(f"AJAX spider start failed: {e}")
            return False

    async def _wait_for_ajax_spider(self, scan_id: str) -> None:
        from backend.api.websocket import emit_tool_output
        start = time.time()
        while time.time() - start < self.max_duration:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(f"{self._zap_api_ajax}/status/")
                    if resp.status_code == 200:
                        data = resp.json()
                        status = data.get("status", "")
                        if status in ("stopped", "error", ""):
                            return
                        await emit_tool_output(scan_id, "zap", f"AJAX spider status: {status}")
            except Exception:
                pass
            await asyncio.sleep(5)

    async def _get_ajax_spider_results(self) -> list[str]:
        urls = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(f"{self._zap_api_ajax}/results/")
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    for item in results:
                        url = item.get("url", "")
                        if url:
                            urls.append(url)
        except Exception as e:
            logger.error(f"Failed to get AJAX spider results: {e}")
        return urls

    async def _get_forms(self) -> list[dict]:
        forms = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(f"{self._zap_api_core}/sites/")
                if resp.status_code == 200:
                    data = resp.json()
                    sites = data.get("sites", [])
                    for site in sites:
                        site_urls = site.get("urls", [])
                        for url_data in site_urls:
                            url = url_data.get("url", "")
                            if url:
                                parsed_forms = await self._get_url_forms(client, url)
                                forms.extend(parsed_forms)
        except Exception as e:
            logger.error(f"Failed to get forms: {e}")
        return forms

    async def _get_url_forms(self, client: httpx.AsyncClient, url: str) -> list[dict]:
        forms = []
        try:
            resp = await client.get(
                f"{self._zap_api_core}/urls/",
                params={"url": url, "recurse": "false"},
            )
            if resp.status_code == 200:
                data = resp.json()
                url_list = data.get("urls", [])
                for item in url_list:
                    if "form" in item.lower() or "?" in item:
                        forms.append({
                            "url": item,
                            "method": "GET" if "?" in item else "POST",
                            "source": "zap",
                        })
        except Exception:
            pass
        return forms

    async def _fallback_crawl(self, target_url: str, scan_id: str) -> dict:
        from backend.api.websocket import emit_tool_output
        from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
        from bs4 import BeautifulSoup

        await emit_tool_output(scan_id, "zap", "Running fallback HTTP-based crawl")

        visited = set()
        queue = asyncio.Queue()
        await queue.put((target_url, 0))
        visited.add(target_url)

        # stay on the target's domain — never follow links to third-party sites
        base_domain = urlparse(target_url).netloc.lower()
        skip_ext = (
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".css", ".js",
            ".pdf", ".zip", ".gz", ".mp3", ".mp4", ".woff", ".woff2", ".ttf",
        )
        max_urls = 60
        max_depth = 3
        workers = 10

        client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=10.0),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            headers={"User-Agent": "InjectGuard-ActiveCrawler/1.0"},
            verify=False,
        )
        crawled = 0
        lock = asyncio.Lock()

        async def worker():
            nonlocal crawled
            while True:
                try:
                    url, depth = await asyncio.wait_for(queue.get(), timeout=10.0)
                except asyncio.TimeoutError:
                    return
                async with lock:
                    if crawled >= max_urls:
                        queue.task_done()
                        return
                    crawled += 1
                try:
                    resp = await client.get(url)
                    soup = BeautifulSoup(resp.text, "html.parser")
                    # extract forms so POST endpoints are never missed
                    for form_tag in soup.find_all("form"):
                        action = urljoin(url, form_tag.get("action", "") or url)
                        method = (form_tag.get("method", "GET") or "GET").upper()
                        fields = []
                        for inp in form_tag.find_all(["input", "select", "textarea"]):
                            name = inp.get("name")
                            if name:
                                fields.append({
                                    "name": name,
                                    "type": inp.get("type", "text"),
                                    "value": inp.get("value", ""),
                                })
                        form_key = (action, method, tuple(sorted(f["name"] for f in fields)))
                        if form_key not in seen_forms:
                            seen_forms.add(form_key)
                            self.discovered_forms.append({
                                "action": action,
                                "method": method,
                                "fields": fields,
                                "source": "fallback",
                            })
                    if depth < max_depth:
                        for a_tag in soup.find_all("a", href=True):
                            full = urljoin(url, a_tag["href"])
                            parsed = urlparse(full)
                            if parsed.scheme not in ("http", "https"):
                                continue
                            if parsed.netloc.lower() != base_domain:
                                continue  # off-site link — out of scope
                            if full.rstrip("/").lower().endswith(skip_ext):
                                continue
                            if full not in visited:
                                visited.add(full)
                                await queue.put((full, depth + 1))
                                self.discovered_urls[full] = {"source": "fallback"}
                except Exception:
                    pass
                queue.task_done()

        seen_forms = set()
        try:
            await asyncio.wait_for(
                asyncio.gather(*(worker() for _ in range(workers))),
                timeout=120,
            )
        except asyncio.TimeoutError:
            await emit_tool_output(scan_id, "zap", "Fallback crawl hit its 120s budget — continuing with URLs found so far", "warn")
        finally:
            await client.aclose()

        await emit_tool_output(
            scan_id, "zap",
            f"Fallback crawl complete: {len(self.discovered_urls)} URLs, {len(self.discovered_forms)} forms",
        )
        return self._compile_results(target_url, 0)

    def _compile_results(self, target_url: str, elapsed: float) -> dict:
        return {
            "target_url": target_url,
            "urls": self.discovered_urls,
            "forms": self.discovered_forms,
            "spider_urls": self.spider_results,
            "ajax_urls": self.ajax_results,
            "total_urls": len(self.discovered_urls),
            "total_forms": len(self.discovered_forms),
            "elapsed_seconds": elapsed,
        }
