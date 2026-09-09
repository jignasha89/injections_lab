import asyncio
import json
import logging
import time
from urllib.parse import urlparse

import httpx

from backend.api.websocket import (
    emit_scan_progress,
    emit_scan_completed,
    emit_scan_error,
    emit_tool_output,
    emit_crawl_update,
    emit_finding,
)
from backend.config import settings
from backend.engine.crawler.passive_crawl import PassiveCrawl
from backend.engine.crawler.active_crawl import ActiveCrawl
from backend.engine.crawler.fuzzer import Fuzzer
from backend.engine.crawler.api_discovery import APIDiscovery
from backend.engine.crawler.surface_mapper import SurfaceMapper

logger = logging.getLogger(__name__)


class DeepCrawl:
    def __init__(self):
        self.passive_crawler = PassiveCrawl(
            max_depth=settings.MAX_DEPTH_DEFAULT,
            concurrency=settings.CONCURRENCY_DEFAULT,
            rate_limit=settings.RATE_LIMIT_DEFAULT,
        )
        self.active_crawler = ActiveCrawl()
        self.fuzzer = Fuzzer()
        self.api_discovery = APIDiscovery()
        self.surface_mapper = SurfaceMapper()
        self.total_requests = 0
        self.total_findings = 0
        self.start_time = 0.0

    async def _guarded(self, coro, budget: float, phase_name: str, fallback, partial=None):
        """Run a crawl phase with a hard time budget: on timeout or crash,
        keep whatever was collected and continue — a slow phase must never
        hang the whole scan. `partial` compiles the crawler's live state so a
        budget overrun returns what it found instead of nothing."""
        def _partial_or_fallback():
            if partial is None:
                return fallback
            try:
                return partial()
            except Exception:
                return fallback

        try:
            return await asyncio.wait_for(coro, timeout=budget)
        except asyncio.TimeoutError:
            logger.warning(f"Phase {phase_name} exceeded {budget}s budget — continuing with partial results")
            await emit_tool_output(self._scan_id_ref[0], "deepcrawl",
                                   f"{phase_name} exceeded {budget}s — continuing with partial results", "warn")
            return _partial_or_fallback()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning(f"Phase {phase_name} failed: {e} — continuing")
            await emit_tool_output(self._scan_id_ref[0], "deepcrawl",
                                   f"Phase {phase_name} failed: {e} — continuing with partial results", "warn")
            return _partial_or_fallback()

    async def run(self, target_url: str, config: dict, scan_id: str) -> dict:
        self.start_time = time.time()
        config = config or {}
        self._scan_id_ref = (scan_id,)

        # defensive normalization: a bare host breaks every downstream request
        if not urlparse(target_url).scheme:
            target_url = "http://" + target_url.lstrip("/")

        # Strict URL validation: must have a non-empty hostname after scheme addition
        parsed = urlparse(target_url)
        if not parsed.netloc:
            error_msg = f"Invalid target URL '{target_url}' — missing host."
            await emit_scan_error(scan_id, error_msg, "deepcrawl")
            return {
                "scan_id": scan_id,
                "target_url": target_url,
                "status": "failed",
                "error": error_msg,
                "duration_seconds": time.time() - self.start_time,
                "total_requests": 0,
                "total_findings": 0,
            }

        # Validate the URL has a netloc (host) after normalization
        parsed = urlparse(target_url)
        if not parsed.netloc:
            error_msg = f"Invalid target URL '{target_url}' — missing host."
            await emit_scan_error(scan_id, error_msg, "deepcrawl")
            return {
                "scan_id": scan_id,
                "target_url": target_url,
                "status": "failed",
                "error": error_msg,
                "duration_seconds": time.time() - self.start_time,
                "total_requests": 0,
                "total_findings": 0,
            }

        try:
            await emit_scan_progress(
                scan_id,
                {
                    "phase": "initial_probe",
                    "percentage": 0.0,
                    "requests_sent": 0,
                    "findings_count": 0,
                    "current_tool": "deepcrawl",
                },
            )

            phase1_results = await self._guarded(
                self._phase1_initial_probe(target_url, scan_id), 30, "initial_probe",
                {"target_url": target_url, "status_code": 0, "headers": {}, "technologies": []},
            )

            # A target that never answers produces a silent empty "success" —
            # fail loudly instead, and if only HTTPS is broken retry over HTTP.
            if phase1_results.get("status_code", 0) == 0:
                if target_url.lower().startswith("https://"):
                    http_url = "http://" + target_url[len("https://"):]
                    await emit_tool_output(
                        scan_id, "deepcrawl",
                        f"HTTPS probe failed for {target_url} — retrying over {http_url}", "warn",
                    )
                    retry = await self._guarded(
                        self._phase1_initial_probe(http_url, scan_id), 30, "initial_probe_http",
                        {"target_url": http_url, "status_code": 0, "headers": {}, "technologies": []},
                    )
                    if retry.get("status_code", 0) > 0:
                        phase1_results = retry
                        target_url = http_url
                        await emit_tool_output(
                            scan_id, "deepcrawl",
                            f"Target reachable over HTTP — continuing with {http_url}", "warn",
                        )
                if phase1_results.get("status_code", 0) == 0:
                    error_msg = (
                        f"Target unreachable: {target_url} — no HTTP response received. "
                        f"Check the URL, scheme (http/https) and network access."
                    )
                    await emit_scan_error(scan_id, error_msg, "deepcrawl")
                    return {
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "status": "failed",
                        "error": error_msg,
                        "duration_seconds": time.time() - self.start_time,
                        "total_requests": self.total_requests,
                        "total_findings": 0,
                    }

            await emit_scan_progress(
                scan_id,
                {
                    "phase": "passive_crawl",
                    "percentage": 10.0,
                    "requests_sent": self.total_requests,
                    "findings_count": self.total_findings,
                    "current_tool": "passive_crawler",
                },
            )

            phase2_results = await self._guarded(
                self._phase2_passive_crawl(target_url, scan_id), 90, "passive_crawl",
                {"urls": {}, "forms": [], "js_files": []},
                partial=lambda: self.passive_crawler._compile_results(target_url),
            )

            await emit_scan_progress(
                scan_id,
                {
                    "phase": "active_crawl",
                    "percentage": 35.0,
                    "requests_sent": self.total_requests,
                    "findings_count": self.total_findings,
                    "current_tool": "zap_spider",
                },
            )

            phase3_results = await self._guarded(
                self._phase3_active_crawl(target_url, scan_id), 180, "active_crawl",
                {"urls": {}, "forms": [], "total_urls": 0, "total_forms": 0},
                partial=lambda: self.active_crawler._compile_results(
                    target_url, time.time() - self.start_time
                ),
            )

            await emit_scan_progress(
                scan_id,
                {
                    "phase": "fuzzing",
                    "percentage": 55.0,
                    "requests_sent": self.total_requests,
                    "findings_count": self.total_findings,
                    "current_tool": "ffuf",
                },
            )

            phase4_results = await self._guarded(
                self._phase4_fuzzing(target_url, scan_id, config), 90, "fuzzing", []
            )

            await emit_scan_progress(
                scan_id,
                {
                    "phase": "api_discovery",
                    "percentage": 75.0,
                    "requests_sent": self.total_requests,
                    "findings_count": self.total_findings,
                    "current_tool": "api_discovery",
                },
            )

            js_files = phase2_results.get("js_files", [])
            phase5_results = await self._guarded(
                self._phase5_api_discovery(target_url, js_files, scan_id), 60, "api_discovery",
                {"total_apis": 0, "total_graphql": 0, "total_openapi": 0},
            )

            await emit_scan_progress(
                scan_id,
                {
                    "phase": "surface_mapping",
                    "percentage": 90.0,
                    "requests_sent": self.total_requests,
                    "findings_count": self.total_findings,
                    "current_tool": "surface_mapper",
                },
            )

            phase6_results = await self._phase6_surface_mapping(
                target_url, phase1_results, phase2_results, phase3_results,
                phase4_results, phase5_results, scan_id,
            )

            elapsed = time.time() - self.start_time

            return {
                "scan_id": scan_id,
                "target_url": target_url,
                "status": "completed",
                "duration_seconds": elapsed,
                "total_requests": self.total_requests,
                "total_findings": self.total_findings,
                "phases": {
                    "initial_probe": phase1_results,
                    "passive_crawl": phase2_results,
                    "active_crawl": phase3_results,
                    "fuzzing": phase4_results,
                    "api_discovery": phase5_results,
                    "surface_mapping": phase6_results,
                },
            }

        except Exception as e:
            logger.error(f"DeepCrawl failed for {target_url}: {e}", exc_info=True)
            elapsed = time.time() - self.start_time
            await emit_scan_error(scan_id, str(e), "deepcrawl")
            return {
                "scan_id": scan_id,
                "target_url": target_url,
                "status": "failed",
                "error": str(e),
                "duration_seconds": elapsed,
                "total_requests": self.total_requests,
                "total_findings": self.total_findings,
            }

    async def _phase1_initial_probe(self, target_url: str, scan_id: str) -> dict:
        await emit_tool_output(scan_id, "deepcrawl", f"Phase 1: Initial probe of {target_url}")

        probe_result = {
            "target_url": target_url,
            "status_code": 0,
            "headers": {},
            "technologies": [],
            "robots_txt": {},
            "sitemap_xml": {},
        }

        async with httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            headers={"User-Agent": "InjectGuard-DeepCrawl/1.0"},
            verify=False,
        ) as client:
            try:
                head_resp = await client.head(target_url)
                self.total_requests += 1
                probe_result["status_code"] = head_resp.status_code
                probe_result["headers"] = dict(head_resp.headers)
                await emit_tool_output(
                    scan_id, "deepcrawl",
                    f"HEAD {target_url} -> {head_resp.status_code}"
                )
            except Exception as e:
                logger.debug(f"HEAD request failed: {e}")
                await emit_tool_output(scan_id, "deepcrawl", f"HEAD request failed: {e}")

            try:
                get_resp = await client.get(target_url)
                self.total_requests += 1
                if probe_result["status_code"] == 0:
                    probe_result["status_code"] = get_resp.status_code
                    probe_result["headers"] = dict(get_resp.headers)
                await emit_tool_output(
                    scan_id, "deepcrawl",
                    f"GET {target_url} -> {get_resp.status_code}"
                )

                probe_result["technologies"] = self._detect_technologies(
                    get_resp.headers, get_resp.text
                )
                await emit_tool_output(
                    scan_id, "deepcrawl",
                    f"Detected technologies: {probe_result['technologies']}"
                )

                robots_urls = await self._parse_robots_txt(client, target_url)
                probe_result["robots_txt"] = robots_urls
                if robots_urls.get("paths"):
                    await emit_tool_output(
                        scan_id, "deepcrawl",
                        f"robots.txt: found {len(robots_urls['paths'])} paths"
                    )

                sitemap_urls = await self._parse_sitemap_xml(client, target_url)
                probe_result["sitemap_xml"] = sitemap_urls
                if sitemap_urls.get("urls"):
                    await emit_tool_output(
                        scan_id, "deepcrawl",
                        f"sitemap.xml: found {len(sitemap_urls['urls'])} URLs"
                    )

            except Exception as e:
                logger.error(f"GET request failed: {e}")
                await emit_tool_output(scan_id, "deepcrawl", f"GET request failed: {e}")

        return probe_result

    def _detect_technologies(self, headers: dict, body: str) -> list[str]:
        technologies = []
        server = headers.get("server", "").lower()
        if server:
            technologies.append(f"server:{server}")
        powered_by = headers.get("x-powered-by", "").lower()
        if powered_by:
            technologies.append(f"powered-by:{powered_by}")
        framework_hints = {
            "laravel": "laravel",
            "django": "django",
            "rails": "ruby-on-rails",
            "express": "express",
            "spring": "spring",
            "asp.net": "aspnet",
            "php": "php",
            "x-generator": "",
        }
        for header_name, tech in framework_hints.items():
            val = headers.get(header_name, "").lower()
            if val and tech:
                technologies.append(tech)
        body_indicators = {
            "wp-content": "wordpress",
            "Drupal": "drupal",
            "Joomla": "joomla",
            "Shopify": "shopify",
            "React": "react",
            "Angular": "angular",
            "Vue.js": "vue",
            "jQuery": "jquery",
            "Next.js": "nextjs",
            "__NEXT_DATA__": "nextjs",
            "nuxt": "nuxt",
            "_app.__nuxt": "nuxt",
        }
        for indicator, tech in body_indicators.items():
            if indicator in body:
                technologies.append(tech)
        return list(set(technologies))

    async def _parse_robots_txt(self, client: httpx.AsyncClient, target_url: str) -> dict:
        result = {"paths": [], "disallowed": [], "sitemap_locations": []}
        try:
            parsed = urlparse(target_url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            resp = await client.get(robots_url)
            self.total_requests += 1
            if resp.status_code == 200:
                content = resp.text
                for line in content.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            result["disallowed"].append(path)
                            result["paths"].append(path)
                    elif line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            result["paths"].append(path)
                    elif line.lower().startswith("sitemap:"):
                        sitemap_loc = line.split(":", 1)[1].strip()
                        result["sitemap_locations"].append(sitemap_loc)
        except Exception as e:
            logger.debug(f"Failed to fetch robots.txt: {e}")
        return result

    async def _parse_sitemap_xml(self, client: httpx.AsyncClient, target_url: str) -> dict:
        result = {"urls": [], "sub_sitemaps": []}
        try:
            parsed = urlparse(target_url)
            sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
            resp = await client.get(sitemap_url)
            self.total_requests += 1
            if resp.status_code == 200:
                content = resp.text
                import re
                url_pattern = re.compile(r'<loc>\s*(.*?)\s*</loc>', re.I | re.S)
                for match in url_pattern.finditer(content):
                    url = match.group(1).strip()
                    if url.endswith(".xml"):
                        result["sub_sitemaps"].append(url)
                    else:
                        result["urls"].append(url)
        except Exception as e:
            logger.debug(f"Failed to fetch sitemap.xml: {e}")
        return result

    async def _phase2_passive_crawl(self, target_url: str, scan_id: str) -> dict:
        await emit_tool_output(scan_id, "deepcrawl", "Phase 2: Passive crawl - BFS traversal")

        passive_results = await self.passive_crawler.run(target_url, scan_id)
        self.total_requests += passive_results.get("total_urls", 0)

        await emit_tool_output(
            scan_id, "deepcrawl",
            f"Passive crawl complete: {passive_results.get('total_urls', 0)} URLs, "
            f"{passive_results.get('total_forms', 0)} forms, "
            f"{passive_results.get('total_params', 0)} params"
        )

        return passive_results

    async def _phase3_active_crawl(self, target_url: str, scan_id: str) -> dict:
        await emit_tool_output(scan_id, "deepcrawl", "Phase 3: Active crawl - ZAP spider")

        active_results = await self.active_crawler.run(target_url, scan_id)
        self.total_requests += active_results.get("total_urls", 0)

        await emit_tool_output(
            scan_id, "deepcrawl",
            f"Active crawl complete: {active_results.get('total_urls', 0)} URLs, "
            f"{active_results.get('total_forms', 0)} forms"
        )

        return active_results

    async def _phase4_fuzzing(
        self, target_url: str, scan_id: str, config: dict
    ) -> list[dict]:
        from backend.api.websocket import emit_scan_progress, emit_tool_output
        import os
        from backend.config import settings

        await emit_tool_output(scan_id, "deepcrawl", "Phase 4: Fuzzing - directory/file/parameter discovery")

        fuzzing_results = []

        # Skip directory fuzzing if ffuf not installed
        if os.path.isfile(settings.FFUF_PATH):
            dir_results = await self.fuzzer.run_directory_fuzz(target_url, scan_id)
            self.total_requests += dir_results.get("total", 0)
            fuzzing_results.append(dir_results)
            await emit_tool_output(
                scan_id, "deepcrawl",
                f"Directory fuzzing: {dir_results.get('total', 0)} results"
            )
        else:
            await emit_tool_output(scan_id, "deepcrawl", f"Ffuf not found at {settings.FFUF_PATH} — skipping directory fuzzing")

        # Skip file fuzzing if ffuf not installed
        if os.path.isfile(settings.FFUF_PATH):
            file_results = await self.fuzzer.run_file_fuzz(target_url, scan_id)
            self.total_requests += file_results.get("total", 0)
            fuzzing_results.append(file_results)
            await emit_tool_output(
                scan_id, "deepcrawl",
                f"File fuzzing: {file_results.get('total', 0)} results"
            )
        else:
            await emit_tool_output(scan_id, "deepcrawl", "Ffuf not found — skipping file fuzzing")

        # Skip parameter fuzzing if ffuf not installed
        if os.path.isfile(settings.FFUF_PATH):
            param_results = await self.fuzzer.run_parameter_fuzz(target_url, scan_id)
            self.total_requests += param_results.get("total", 0)
            fuzzing_results.append(param_results)
            await emit_tool_output(
                scan_id, "deepcrawl",
                f"Parameter fuzzing: {param_results.get('total', 0)} results"
            )
        else:
            await emit_tool_output(scan_id, "deepcrawl", "Ffuf not found — skipping parameter fuzzing")

        # Skip vhost fuzzing if ffuf not installed
        if os.path.isfile(settings.FFUF_PATH):
            vhost_results = await self.fuzzer.run_vhost_fuzz(target_url, scan_id)
            self.total_requests += vhost_results.get("total", 0)
            fuzzing_results.append(vhost_results)
            await emit_tool_output(
                scan_id, "deepcrawl",
                f"Vhost fuzzing: {vhost_results.get('total', 0)} results"
            )
        else:
            await emit_tool_output(scan_id, "deepcrawl", "Ffuf not found — skipping vhost fuzzing")

        return fuzzing_results

    async def _phase5_api_discovery(
        self, target_url: str, js_files: list[str], scan_id: str
    ) -> dict:
        await emit_tool_output(scan_id, "deepcrawl", "Phase 5: API discovery - JS analysis & GraphQL")

        api_results = await self.api_discovery.run(target_url, js_files, scan_id)

        await emit_tool_output(
            scan_id, "deepcrawl",
            f"API discovery complete: {api_results.get('total_apis', 0)} endpoints, "
            f"{api_results.get('total_graphql', 0)} GraphQL, "
            f"{api_results.get('total_openapi', 0)} OpenAPI docs"
        )

        return api_results

    async def _phase6_surface_mapping(
        self,
        target_url: str,
        phase1: dict,
        phase2: dict,
        phase3: dict,
        phase4: list[dict],
        phase5: dict,
        scan_id: str,
    ) -> dict:
        await emit_tool_output(scan_id, "deepcrawl", "Phase 6: Attack surface mapping")

        surface_map = self.surface_mapper.compile(
            passive_results=phase2,
            active_results=phase3,
            fuzzing_results=phase4,
            api_results=phase5,
            initial_probe=phase1,
        )

        summary = surface_map.get("summary", {})
        self.total_findings = summary.get("total_risk_indicators", 0)

        await emit_tool_output(
            scan_id, "deepcrawl",
            f"Surface mapping complete: "
            f"{summary.get('total_urls', 0)} URLs, "
            f"{summary.get('total_forms', 0)} forms, "
            f"{summary.get('total_api_endpoints', 0)} APIs, "
            f"{summary.get('total_risk_indicators', 0)} risk indicators"
        )

        risk_counts = summary.get("risk_counts", {})
        if risk_counts.get("high", 0) > 0:
            high_risks = self.surface_mapper.get_risk_indicators("high")
            for risk in high_risks[:10]:
                await emit_finding(scan_id, {
                    "type": "surface_risk",
                    "severity": risk.get("risk", "high"),
                    "url": risk.get("url", ""),
                    "detail": risk.get("detail", ""),
                    "indicator_type": risk.get("type", ""),
                })

        return surface_map

    def _build_severity_summary(self, surface_map: dict) -> dict:
        summary = surface_map.get("summary", {})
        risk_counts = summary.get("risk_counts", {})
        return {
            "critical": 0,
            "high": risk_counts.get("high", 0),
            "medium": risk_counts.get("medium", 0),
            "low": risk_counts.get("low", 0),
            "info": summary.get("total_urls", 0),
        }
