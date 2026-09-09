import asyncio
import json
import logging
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from backend.api.websocket import emit_tool_output

logger = logging.getLogger(__name__)

FETCH_PATTERNS = [
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'fetch\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\$\.\s*(?:ajax|get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\']\s*,\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'XMLHttpRequest.*?\.open\s*\(\s*["\'][^"\']+["\']\s*,\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'(?:http|https)\.request\s*\(\s*["\']([^"\']+)["\']', re.I),
]

API_PATH_PATTERNS = [
    re.compile(r'/api/[a-zA-Z0-9_\-/]+', re.I),
    re.compile(r'/v[0-9]+/[a-zA-Z0-9_\-/]+', re.I),
    re.compile(r'/graphql', re.I),
    re.compile(r'/rest/[a-zA-Z0-9_\-/]+', re.I),
    re.compile(r'/webapi/[a-zA-Z0-9_\-/]+', re.I),
    re.compile(r'/service/[a-zA-Z0-9_\-/]+', re.I),
    re.compile(r'/endpoint/[a-zA-Z0-9_\-/]+', re.I),
    re.compile(r'/action/[a-zA-Z0-9_\-/]+', re.I),
]

GRAPHQL_PATTERNS = [
    re.compile(r'query\s+\w+\s*\(', re.I),
    re.compile(r'mutation\s+\w+\s*\(', re.I),
    re.compile(r'subscription\s+\w+\s*\(', re.I),
    re.compile(r'__schema', re.I),
    re.compile(r'__type', re.I),
    re.compile(r'graphql\s*\(\s*["\']([^"\']+)["\']', re.I),
]

SWAGGER_PATTERNS = [
    re.compile(r'swagger\.json', re.I),
    re.compile(r'swagger\.yaml', re.I),
    re.compile(r'openapi\.json', re.I),
    re.compile(r'openapi\.yaml', re.I),
    re.compile(r'api-docs', re.I),
    re.compile(r'v[0-9]+/api-docs', re.I),
]

IMPORT_PATTERN = re.compile(
    r'(?:import|require)\s*\(\s*["\']([^"\']+\.(?:js|ts|jsx|tsx))["\']', re.I
)

COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/graphql",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/docs",
    "/redoc",
    "/swagger-ui",
    "/.well-known/openapi.json",
]


class APIDiscovery:
    def __init__(
        self,
        timeout: float = 30.0,
        max_js_files: int = 50,
        concurrency: int = 10,
    ):
        self.timeout = timeout
        self.max_js_files = max_js_files
        self.concurrency = concurrency
        self.discovered_apis: dict[str, dict] = {}
        self.js_files_analyzed: list[str] = []
        self.graphql_endpoints: list[dict] = []
        self.openapi_docs: list[dict] = []
        self._semaphore: asyncio.Semaphore | None = None

    async def run(
        self,
        target_url: str,
        js_files: list[str] | None = None,
        scan_id: str = "",
    ) -> dict:
        from backend.api.websocket import emit_scan_progress, emit_tool_output

        self._semaphore = asyncio.Semaphore(self.concurrency)
        await emit_tool_output(scan_id, "api_discovery", f"Starting API discovery on {target_url}")
        await emit_scan_progress(
            scan_id,
            {
                "phase": "api_discovery",
                "percentage": 78.0,
                "requests_sent": 0,
                "findings_count": 0,
                "current_tool": "api_discovery",
            },
        )

        js_urls = js_files or []
        if not js_urls:
            js_urls = await self._discover_js_files(target_url, scan_id)

        await emit_tool_output(
            scan_id, "api_discovery",
            f"Analyzing {len(js_urls)} JavaScript files..."
        )

        js_tasks = [self._analyze_js_file(js_url, scan_id) for js_url in js_urls[:self.max_js_files]]
        await asyncio.gather(*js_tasks, return_exceptions=True)

        await emit_tool_output(scan_id, "api_discovery", "Checking for OpenAPI/Swagger docs...")
        await self._check_openapi_docs(target_url, scan_id)

        await emit_tool_output(scan_id, "api_discovery", "Checking for GraphQL endpoints...")
        await self._check_graphql_endpoints(target_url, scan_id)

        await emit_scan_progress(
            scan_id,
            {
                "phase": "api_discovery",
                "percentage": 85.0,
                "requests_sent": len(self.js_files_analyzed),
                "findings_count": len(self.discovered_apis),
                "current_tool": "api_discovery",
            },
        )

        await emit_tool_output(
            scan_id, "api_discovery",
            f"API discovery complete. Found {len(self.discovered_apis)} endpoints, "
            f"{len(self.graphql_endpoints)} GraphQL endpoints, "
            f"{len(self.openapi_docs)} OpenAPI docs"
        )

        return self._compile_results(target_url)

    async def _discover_js_files(self, target_url: str, scan_id: str) -> list[str]:
        js_files = []
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                headers={"User-Agent": "InjectGuard-APIDiscovery/1.0"},
                verify=False,
            ) as client:
                resp = await client.get(target_url)
                if resp.status_code != 200:
                    return js_files

                soup = BeautifulSoup(resp.text, "html.parser")
                for script_tag in soup.find_all("script"):
                    src = script_tag.get("src", "")
                    if src:
                        full_url = urljoin(target_url, src)
                        js_files.append(full_url)
                    else:
                        content = script_tag.string or ""
                        if content:
                            await self._extract_js_imports(content, target_url, js_files)

                for link_tag in soup.find_all("link", href=True):
                    href = link_tag.get("href", "")
                    rel = link_tag.get("rel", [])
                    if isinstance(rel, str):
                        rel = [rel]
                    if "preload" in rel or "prefetch" in rel:
                        full_url = urljoin(target_url, href)
                        if full_url.endswith((".js", ".mjs", ".chunk.js")):
                            js_files.append(full_url)

        except Exception as e:
            logger.error(f"Failed to discover JS files: {e}")

        await emit_tool_output(scan_id, "api_discovery", f"Found {len(js_files)} JavaScript files")
        return list(set(js_files))

    async def _extract_js_imports(
        self, js_content: str, base_url: str, js_files: list[str]
    ) -> None:
        for match in IMPORT_PATTERN.finditer(js_content):
            import_path = match.group(1)
            full_url = urljoin(base_url, import_path)
            if full_url not in js_files:
                js_files.append(full_url)

    async def _analyze_js_file(self, js_url: str, scan_id: str) -> None:
        from backend.api.websocket import emit_tool_output

        async with self._semaphore:
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    resp = await client.get(js_url)
                    if resp.status_code != 200:
                        return

                    content = resp.text
                    self.js_files_analyzed.append(js_url)

                    endpoints = self._extract_endpoints_from_js(content, js_url)
                    for endpoint, endpoint_info in endpoints.items():
                        if endpoint not in self.discovered_apis:
                            self.discovered_apis[endpoint] = endpoint_info
                            await emit_tool_output(
                                scan_id, "api_discovery",
                                f"Found API endpoint: {endpoint} (from {js_url})"
                            )

                    graphql_found = self._detect_graphql_in_js(content, js_url)
                    self.graphql_endpoints.extend(graphql_found)

            except Exception as e:
                logger.debug(f"Failed to analyze JS file {js_url}: {e}")

    def _extract_endpoints_from_js(self, js_content: str, source_url: str) -> dict[str, dict]:
        endpoints = {}
        for pattern in FETCH_PATTERNS:
            for match in pattern.finditer(js_content):
                endpoint = match.group(1)
                if self._is_valid_endpoint(endpoint):
                    normalized = self._normalize_endpoint(endpoint, source_url)
                    endpoints[normalized] = {
                        "url": normalized,
                        "source": source_url,
                        "method": self._guess_method(pattern, js_content, match.start()),
                        "type": "javascript_fetch",
                    }

        for pattern in API_PATH_PATTERNS:
            for match in pattern.finditer(js_content):
                endpoint = match.group(0)
                normalized = self._normalize_endpoint(endpoint, source_url)
                if normalized not in endpoints:
                    endpoints[normalized] = {
                        "url": normalized,
                        "source": source_url,
                        "method": "UNKNOWN",
                        "type": "api_path_pattern",
                    }

        # OAuth endpoint detection
        oauth_patterns = [
            re.compile(r'/oauth(?:2)?/authorize', re.I),
            re.compile(r'/oauth(?:2)?/token', re.I),
            re.compile(r'/\.well-known/openid-configuration', re.I),
            re.compile(r'/oauth2/callback', re.I)
        ]
        for pattern in oauth_patterns:
            for match in pattern.finditer(js_content):
                endpoint = match.group(0)
                normalized = self._normalize_endpoint(endpoint, source_url)
                if normalized not in endpoints:
                    endpoints[normalized] = {
                        "url": normalized,
                        "source": source_url,
                        "method": "GET",
                        "type": "oauth_endpoint"
                    }

        return endpoints

    def _detect_graphql_in_js(self, js_content: str, source_url: str) -> list[dict]:
        graphql_endpoints = []
        for pattern in GRAPHQL_PATTERNS:
            for match in pattern.finditer(js_content):
                query_text = js_content[max(0, match.start() - 200):match.end() + 200]
                endpoint_match = re.search(
                    r'(?:url|endpoint|uri)\s*[:=]\s*["\']([^"\']*graphql[^"\']*)["\']',
                    query_text, re.I
                )
                graphql_url = endpoint_match.group(1) if endpoint_match else "/graphql"
                normalized = self._normalize_endpoint(graphql_url, source_url)
                graphql_endpoints.append({
                    "url": normalized,
                    "source": source_url,
                    "query_preview": match.group(0)[:100],
                    "type": "graphql",
                })
        return graphql_endpoints

    async def _check_openapi_docs(self, target_url: str, scan_id: str) -> None:
        from backend.api.websocket import emit_tool_output
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        paths_to_check = COMMON_API_PATHS + [
            "/swagger.json",
            "/swagger/v1/swagger.json",
            "/openapi.json",
            "/openapi/v1/openapi.json",
            "/api/swagger.json",
            "/api/openapi.json",
        ]

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,
        ) as client:
            for path in paths_to_check:
                try:
                    url = f"{base}{path}"
                    resp = await client.get(url, headers={"Accept": "application/json"})
                    if resp.status_code == 200:
                        content_type = resp.headers.get("content-type", "")
                        if "json" in content_type or "yaml" in content_type:
                            try:
                                data = resp.json()
                                if self._is_valid_openapi_doc(data):
                                    version = data.get("openapi", data.get("swagger", "unknown"))
                                    title = data.get("info", {}).get("title", "Unknown API")
                                    paths_count = len(data.get("paths", {}))
                                    self.openapi_docs.append({
                                        "url": url,
                                        "version": str(version),
                                        "title": title,
                                        "paths_count": paths_count,
                                        "type": "openapi",
                                    })
                                    await emit_tool_output(
                                        scan_id, "api_discovery",
                                        f"Found OpenAPI doc: {url} (v{version}, {title}, {paths_count} paths)"
                                    )
                                    self.discovered_apis[url] = {
                                        "url": url,
                                        "source": "openapi_discovery",
                                        "method": "GET",
                                        "type": "openapi_doc",
                                    }
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    continue

    def _is_valid_openapi_doc(self, data: dict) -> bool:
        if "openapi" in data or "swagger" in data:
            if "paths" in data or "info" in data:
                return True
        return False

    async def _check_graphql_endpoints(self, target_url: str, scan_id: str) -> None:
        from backend.api.websocket import emit_tool_output
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        graphql_paths = ["/graphql", "/graphiql", "/v1/graphql", "/v2/graphql", "/api/graphql"]

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,
        ) as client:
            for path in graphql_paths:
                try:
                    url = f"{base}{path}"
                    introspection_query = {
                        "query": "{ __schema { queryType { name } mutationType { name } types { name kind } } }"
                    }
                    resp = await client.post(
                        url,
                        json=introspection_query,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if "data" in data and data["data"] is not None:
                            schema = data["data"].get("__schema", {})
                            types = schema.get("types", [])
                            query_type = schema.get("queryType", {}).get("name", "")
                            mutation_type = schema.get("mutationType", {}).get("name", "")
                            
                            # Extract fields/args as parameters
                            fields = []
                            for t in types:
                                if t.get("name") in [query_type, mutation_type]:
                                    for field in t.get("fields") or []:
                                        fields.append(field.get("name"))
                                        for arg in field.get("args") or []:
                                            fields.append(arg.get("name"))

                            self.graphql_endpoints.append({
                                "url": url,
                                "source": "introspection",
                                "query_type": query_type,
                                "mutation_type": mutation_type,
                                "types_count": len(types),
                                "fields_extracted": len(fields),
                                "type": "graphql_introspection",
                            })
                            self.discovered_apis[url] = {
                                "url": url,
                                "source": "graphql_introspection",
                                "method": "POST",
                                "type": "graphql",
                                "parameters": list(set(fields)) # Add extracted fields as injectable parameters
                            }
                            await emit_tool_output(
                                scan_id, "api_discovery",
                                f"GraphQL introspection enabled at {url} "
                                f"(query: {query_type}, mutation: {mutation_type}, types: {len(types)})"
                            )
                except Exception:
                    continue

    def _is_valid_endpoint(self, endpoint: str) -> bool:
        if not endpoint or len(endpoint) < 2:
            return False
        skip = [
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
            ".woff2", ".ttf", ".eot", ".map", ".min.js",
        ]
        lower = endpoint.lower()
        for s in skip:
            if lower.endswith(s):
                return False
        if endpoint.startswith(("#", "javascript:", "mailto:", "tel:")):
            return False
        if endpoint.startswith("//"):
            return False
        return True

    def _normalize_endpoint(self, endpoint: str, source_url: str) -> str:
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint
        parsed_source = urlparse(source_url)
        base = f"{parsed_source.scheme}://{parsed_source.netloc}"
        if endpoint.startswith("/"):
            return f"{base}{endpoint}"
        return urljoin(source_url, endpoint)

    def _guess_method(self, pattern: re.Pattern, content: str, match_pos: int) -> str:
        context = content[max(0, match_pos - 50):match_pos + 200]
        context_lower = context.lower()
        if "post" in context_lower or ".post(" in context_lower:
            return "POST"
        if "put" in context_lower or ".put(" in context_lower:
            return "PUT"
        if "delete" in context_lower or ".delete(" in context_lower:
            return "DELETE"
        if "patch" in context_lower or ".patch(" in context_lower:
            return "PATCH"
        return "GET"

    def _compile_results(self, target_url: str) -> dict:
        return {
            "target_url": target_url,
            "apis": self.discovered_apis,
            "graphql_endpoints": self.graphql_endpoints,
            "openapi_docs": self.openapi_docs,
            "js_files_analyzed": self.js_files_analyzed,
            "total_apis": len(self.discovered_apis),
            "total_graphql": len(self.graphql_endpoints),
            "total_openapi": len(self.openapi_docs),
            "total_js_files": len(self.js_files_analyzed),
        }
