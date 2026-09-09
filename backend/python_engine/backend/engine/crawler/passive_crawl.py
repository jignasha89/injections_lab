import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

JS_FRAMEWORK_PATTERNS = [
    re.compile(r"react[.\-]", re.I),
    re.compile(r"angular[.\-]", re.I),
    re.compile(r"vue[.\-]", re.I),
    re.compile(r"jquery[.\-]", re.I),
    re.compile(r"next[.\-]js", re.I),
    re.compile(r"nuxt", re.I),
    re.compile(r"svelte", re.I),
    re.compile(r"ember", re.I),
    re.compile(r"backbone", re.I),
]

FORM_PARAM_PATTERNS = [
    re.compile(r"name\s*=\s*[\"']([^\"']+)[\"']", re.I),
    re.compile(r"\.value\s*=", re.I),
    re.compile(r"getElementById\s*\(\s*[\"']([^\"']+)[\"']", re.I),
    re.compile(r"querySelector\s*\(\s*[\"'][^\"']*name\s*=\s*[\"']([^\"']+)[\"']", re.I),
]

ENDPOINT_PATTERNS = [
    re.compile(r"(?:fetch|axios|XMLHttpRequest|ajax)\s*\(\s*[\"']([^\"']+)[\"']", re.I),
    re.compile(r"(?:get|post|put|delete|patch)\s*\(\s*[\"']([^\"']+)[\"']", re.I),
    re.compile(r"\/api\/[a-zA-Z0-9_\-\/]+", re.I),
    re.compile(r"\/v[0-9]+\/[a-zA-Z0-9_\-\/]+", re.I),
]

JS_SRC_PATTERN = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
INLINE_JS_PATTERN = re.compile(r'<script[^>]*>(.*?)</script>', re.I | re.S)


class PassiveCrawl:
    def __init__(
        self,
        max_depth: int = 5,
        concurrency: int = 10,
        rate_limit: float = 10.0,
        timeout: float = 30.0,
    ):
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.visited: set[str] = set()
        self.discovered_urls: dict[str, dict] = {}
        self.discovered_forms: list[dict] = []
        self.discovered_params: set[str] = set()
        self.discovered_js_files: list[str] = []
        self.discovered_endpoints: set[str] = set()
        self.js_frameworks: set[str] = set()
        self.max_urls = 150
        self._semaphore: asyncio.Semaphore | None = None

    async def run(self, target_url: str, scan_id: str = "") -> dict:
        from backend.api.websocket import emit_crawl_update, emit_scan_progress

        self._semaphore = asyncio.Semaphore(self.concurrency)
        base_url = self._normalize_url(target_url)
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        await queue.put((base_url, 0))
        self.visited.add(base_url)
        total_requests = 0

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=10.0),
            follow_redirects=True,
            headers={"User-Agent": "InjectGuard-PassiveCrawler/1.0"},
            verify=False,
        ) as client:
            while not queue.empty():
                # hard cap keeps large sites inside the phase budget
                if len(self.visited) >= self.max_urls:
                    break
                batch: list[tuple[str, int]] = []
                while not queue.empty() and len(batch) < self.concurrency:
                    try:
                        batch.append(queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break

                tasks = [
                    self._crawl_page(client, url, depth, scan_id, queue)
                    for url, depth in batch
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, dict):
                        total_requests += result.get("requests", 0)

                if total_requests % 50 == 0 and total_requests > 0:
                    await emit_scan_progress(
                        scan_id,
                        {
                            "phase": "passive_crawl",
                            "percentage": min(30.0, total_requests * 0.5),
                            "requests_sent": total_requests,
                            "findings_count": len(self.discovered_urls),
                            "current_tool": "passive_crawler",
                        },
                    )

        return self._compile_results(target_url)

    async def _crawl_page(
        self,
        client: httpx.AsyncClient,
        url: str,
        depth: int,
        scan_id: str,
        queue: asyncio.Queue,
    ) -> dict:
        from backend.api.websocket import emit_crawl_update

        requests_count = 0
        async with self._semaphore:
            try:
                response = await client.get(url)
                requests_count = 1
            except Exception as e:
                logger.debug(f"Failed to fetch {url}: {e}")
                return {"requests": requests_count}

            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                self.discovered_urls[url] = {
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "depth": depth,
                    "title": "",
                    "forms": [],
                    "scripts": [],
                }
                return {"requests": requests_count}

            soup = BeautifulSoup(response.text, "html.parser")
            title_tag = soup.find("title")
            title = title_tag.get_text(strip=True) if title_tag else ""

            page_forms = self._extract_forms(soup, url)
            page_scripts = self._extract_scripts(soup, url)
            page_links = self._extract_links(soup, url)
            page_params = self._extract_params_from_html(response.text)

            self.discovered_urls[url] = {
                "status_code": response.status_code,
                "content_type": content_type,
                "depth": depth,
                "title": title,
                "forms": page_forms,
                "scripts": page_scripts,
            }
            self.discovered_forms.extend(page_forms)
            self.discovered_params.update(page_params)

            for script_url in page_scripts:
                if script_url not in self.discovered_js_files:
                    self.discovered_js_files.append(script_url)

            for link in page_links:
                parsed_link = urlparse(link)
                link_host = parsed_link.netloc.split(":")[0].lower()
                base_host = self.base_domain.split(":")[0].lower()
                in_scope = link_host == base_host or link_host.endswith("." + base_host)
                if (
                    in_scope
                    and link not in self.visited
                    and len(self.visited) < self.max_urls
                ):
                    if depth < self.max_depth:
                        self.visited.add(link)
                        await queue.put((link, depth + 1))
                        await emit_crawl_update(
                            scan_id,
                            {
                                "new_url": link,
                                "element_type": "link",
                                "source": url,
                            },
                        )

            return {"requests": requests_count}

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list[dict]:
        forms = []
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            method = form_tag.get("method", "GET").upper()
            form_url = urljoin(page_url, action) if action else page_url
            
            form_type = "unknown"
            if any(term in action.lower() for term in ["mail", "smtp", "send", "contact"]):
                form_type = "email_form"

            fields = []
            for input_tag in form_tag.find_all(["input", "select", "textarea"]):
                field_name = input_tag.get("name", "")
                field_type = input_tag.get("type", "text")
                
                if input_tag.name == "textarea":
                    field_type = "message_field"
                elif field_type == "file":
                    field_type = "file_upload"
                elif field_type == "email":
                    field_type = "email_fields"
                elif form_type == "email_form" and field_type in ("text", "hidden"):
                    field_type = "email_fields"

                if field_name:
                    field_data = {
                        "name": field_name,
                        "type": field_type,
                        "value": input_tag.get("value", ""),
                    }
                    if input_tag.name == "select":
                        field_data["options"] = [
                            opt.get("value", "") for opt in input_tag.find_all("option")
                        ]
                    fields.append(field_data)
                    self.discovered_params.add(field_name)

            forms.append({
                "action": form_url,
                "method": method,
                "fields": fields,
                "enctype": form_tag.get("enctype", "application/x-www-form-urlencoded"),
            })

        return forms

    def _extract_scripts(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        scripts = []
        for script_tag in soup.find_all("script"):
            src = script_tag.get("src", "")
            if src:
                script_url = urljoin(page_url, src)
                scripts.append(script_url)
                self._detect_framework(src)
            else:
                content = script_tag.string or ""
                if content:
                    self._extract_endpoints_from_js(content, page_url)
        return scripts

    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        links = []
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full_url = urljoin(page_url, href)
            parsed = urlparse(full_url)
            if parsed.scheme in ("http", "https"):
                normalized = self._normalize_url(full_url)
                links.append(normalized)
        return links

    def _extract_params_from_html(self, html: str) -> set[str]:
        params = set()
        for pattern in FORM_PARAM_PATTERNS:
            for match in pattern.finditer(html):
                params.add(match.group(1))
        query_pattern = re.compile(r'[?&](\w+)=', re.I)
        for match in query_pattern.finditer(html):
            params.add(match.group(1))
        return params

    def _detect_framework(self, src: str) -> None:
        for pattern in JS_FRAMEWORK_PATTERNS:
            if pattern.search(src):
                framework = pattern.pattern.replace("[.\\-]", "").replace("[.-]", "")
                self.js_frameworks.add(framework)

    def _extract_endpoints_from_js(self, js_content: str, source_url: str) -> None:
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(js_content):
                endpoint = match.group(1) if match.lastindex else match.group(0)
                if endpoint.startswith("/"):
                    parsed_source = urlparse(source_url)
                    endpoint = f"{parsed_source.scheme}://{parsed_source.netloc}{endpoint}"
                self.discovered_endpoints.add(endpoint)

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        # keep the query string: index.jsp?content=X is a distinct page with
        # its own injectable parameters — stripping it collapses the whole
        # site onto a handful of URLs
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            parsed.query,
            "",
        ))

    def _compile_results(self, target_url: str) -> dict:
        return {
            "target_url": target_url,
            "urls": self.discovered_urls,
            "forms": self.discovered_forms,
            "params": list(self.discovered_params),
            "js_files": self.discovered_js_files,
            "endpoints": list(self.discovered_endpoints),
            "js_frameworks": list(self.js_frameworks),
            "total_urls": len(self.discovered_urls),
            "total_forms": len(self.discovered_forms),
            "total_params": len(self.discovered_params),
            "total_js_files": len(self.discovered_js_files),
            "total_endpoints": len(self.discovered_endpoints),
        }
