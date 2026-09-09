import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)

URL_CLASSIFICATION_PATTERNS = {
    "api_endpoint": [
        re.compile(r'/api/', re.I),
        re.compile(r'/v[0-9]+/', re.I),
        re.compile(r'/graphql', re.I),
        re.compile(r'/rest/', re.I),
        re.compile(r'\.json$', re.I),
        re.compile(r'\.xml$', re.I),
    ],
    "auth_endpoint": [
        re.compile(r'/login', re.I),
        re.compile(r'/auth', re.I),
        re.compile(r'/signup', re.I),
        re.compile(r'/register', re.I),
        re.compile(r'/token', re.I),
        re.compile(r'/oauth', re.I),
        re.compile(r'/sso', re.I),
        re.compile(r'/session', re.I),
    ],
    "admin_panel": [
        re.compile(r'/admin', re.I),
        re.compile(r'/dashboard', re.I),
        re.compile(r'/manage', re.I),
        re.compile(r'/console', re.I),
        re.compile(r'/panel', re.I),
        re.compile(r'/cms', re.I),
    ],
    "file_upload": [
        re.compile(r'/upload', re.I),
        re.compile(r'/file', re.I),
        re.compile(r'/import', re.I),
        re.compile(r'/attach', re.I),
    ],
    "search": [
        re.compile(r'/search', re.I),
        re.compile(r'/query', re.I),
        re.compile(r'/find', re.I),
        re.compile(r'/lookup', re.I),
    ],
    "user_content": [
        re.compile(r'/profile', re.I),
        re.compile(r'/user', re.I),
        re.compile(r'/account', re.I),
        re.compile(r'/settings', re.I),
    ],
    "static_resource": [
        re.compile(r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$', re.I),
    ],
    "webpage": [
        re.compile(r'\.html?$', re.I),
        re.compile(r'\.php$', re.I),
        re.compile(r'\.asp$', re.I),
        re.compile(r'\.jsp$', re.I),
    ],
    "log_endpoint": [
        re.compile(r'/log', re.I),
        re.compile(r'/audit', re.I),
        re.compile(r'/track', re.I),
        re.compile(r'/analytics', re.I),
    ],
    "ai_endpoint": [
        re.compile(r'/chat', re.I),
        re.compile(r'/prompt', re.I),
        re.compile(r'/completions', re.I),
        re.compile(r'/generate', re.I),
        re.compile(r'/ask', re.I),
    ],
}

SENSITIVE_PARAM_PATTERNS = [
    re.compile(r'(?:pass|password|pwd)', re.I),
    re.compile(r'(?:token|jwt|auth)', re.I),
    re.compile(r'(?:key|apikey|api_key)', re.I),
    re.compile(r'(?:secret|secret_key)', re.I),
    re.compile(r'(?:session|sid)', re.I),
    re.compile(r'(?:email|e-mail)', re.I),
    re.compile(r'(?:phone|mobile|tel)', re.I),
    re.compile(r'(?:ssn|social)', re.I),
    re.compile(r'(?:credit_card|card_number|cc)', re.I),
    re.compile(r'(?:file|path|dir|folder)', re.I),
    re.compile(r'(?:url|redirect|return)', re.I),
    re.compile(r'(?:id|user_id|account_id)', re.I),
    re.compile(r'(?:admin|role|permission)', re.I),
]

AI_PARAM_PATTERNS = [
    re.compile(r'(?:prompt|query|message|input|instruction|context|user_message)', re.I),
]


class SurfaceMapper:
    def __init__(self):
        self.surface_map: dict = {}
        self.all_urls: dict[str, dict] = {}
        self.all_forms: list[dict] = []
        self.all_params: set[str] = set()
        self.all_endpoints: set[str] = set()
        self.all_js_files: list[str] = []
        self.all_apis: dict[str, dict] = {}
        self.all_graphql: list[dict] = []
        self.all_openapi: list[dict] = []
        self.classifications: dict[str, list[str]] = {}
        self.risk_indicators: list[dict] = []

    def compile(
        self,
        passive_results: dict | None = None,
        active_results: dict | None = None,
        fuzzing_results: list[dict] | None = None,
        api_results: dict | None = None,
        initial_probe: dict | None = None,
    ) -> dict:
        if initial_probe:
            self._merge_initial_probe(initial_probe)
        if passive_results:
            self._merge_passive_results(passive_results)
        if active_results:
            self._merge_active_results(active_results)
        if fuzzing_results:
            self._merge_fuzzing_results(fuzzing_results)
        if api_results:
            self._merge_api_results(api_results)

        self._classify_all_urls()
        self._identify_risk_indicators()
        self._deduplicate()

        self.surface_map = {
            "summary": self._build_summary(),
            "urls": self._build_url_map(),
            "forms": self._build_form_map(),
            "parameters": self._build_param_map(),
            "api_endpoints": self._build_api_map(),
            "graphql_endpoints": self.all_graphql,
            "openapi_documents": self.all_openapi,
            "js_files": self.all_js_files,
            "classifications": self.classifications,
            "risk_indicators": self.risk_indicators,
            "technology_stack": self._extract_tech_stack(passive_results),
        }

        return self.surface_map

    def _merge_initial_probe(self, probe: dict) -> None:
        target_url = probe.get("target_url", "")
        if target_url:
            self.all_urls[target_url] = {
                "status_code": probe.get("status_code", 0),
                "headers": probe.get("headers", {}),
                "technologies": probe.get("technologies", []),
                "source": "initial_probe",
            }
        robots = probe.get("robots_txt", {})
        if robots:
            for path in robots.get("paths", []):
                url = f"{probe.get('target_url', '')}{path}"
                self.all_urls[url] = {
                    "status_code": 200,
                    "source": "robots_txt",
                    "type": "robots_entry",
                }
        sitemap = probe.get("sitemap_xml", {})
        if sitemap:
            for url in sitemap.get("urls", []):
                self.all_urls[url] = {
                    "status_code": 200,
                    "source": "sitemap_xml",
                    "type": "sitemap_entry",
                }

    def _merge_passive_results(self, results: dict) -> None:
        urls = results.get("urls", {})
        for url, info in urls.items():
            if url not in self.all_urls:
                self.all_urls[url] = info
            else:
                self.all_urls[url].update(info)

        self.all_forms.extend(results.get("forms", []))
        self.all_params.update(results.get("params", []))
        self.all_js_files.extend(results.get("js_files", []))
        self.all_endpoints.update(results.get("endpoints", []))

    def _merge_active_results(self, results: dict) -> None:
        urls = results.get("urls", {})
        for url, info in urls.items():
            if url not in self.all_urls:
                self.all_urls[url] = info
            else:
                self.all_urls[url].update(info)

        self.all_forms.extend(results.get("forms", []))

    def _merge_fuzzing_results(self, results_list: list[dict]) -> None:
        for result in results_list:
            results = result.get("results", [])
            for item in results:
                url = item.get("url", "")
                if url:
                    self.all_urls[url] = {
                        "status_code": item.get("status", 0),
                        "length": item.get("length", 0),
                        "source": f"fuzzing_{result.get('type', 'unknown')}",
                        "fuzz_input": item.get("input", ""),
                    }

    def _merge_api_results(self, results: dict) -> None:
        apis = results.get("apis", {})
        self.all_apis.update(apis)
        self.all_graphql.extend(results.get("graphql_endpoints", []))
        self.all_openapi.extend(results.get("openapi_docs", []))
        self.all_js_files.extend(results.get("js_files_analyzed", []))

    def _classify_all_urls(self) -> None:
        self.classifications = {cat: [] for cat in URL_CLASSIFICATION_PATTERNS}
        self.classifications["other"] = []

        for url in self.all_urls:
            classified = False
            for category, patterns in URL_CLASSIFICATION_PATTERNS.items():
                for pattern in patterns:
                    if pattern.search(url):
                        self.classifications[category].append(url)
                        classified = True
                        break
                if classified:
                    break
            if not classified:
                self.classifications["other"].append(url)

    def _identify_risk_indicators(self) -> None:
        self.risk_indicators = []

        for url in self.all_urls:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            for param_name in query_params:
                for pattern in SENSITIVE_PARAM_PATTERNS:
                    if pattern.search(param_name):
                        self.risk_indicators.append({
                            "type": "sensitive_parameter",
                            "url": url,
                            "parameter": param_name,
                            "risk": "high",
                            "detail": f"URL contains potentially sensitive parameter: {param_name}",
                        })
                        break

            for param_name in query_params:
                for pattern in AI_PARAM_PATTERNS:
                    if pattern.search(param_name):
                        self.risk_indicators.append({
                            "type": "ai_input_parameter",
                            "url": url,
                            "parameter": param_name,
                            "risk": "medium",
                            "detail": f"URL contains AI input parameter: {param_name}",
                        })
                        break

        for form in self.all_forms:
            for field in form.get("fields", []):
                field_name = field.get("name", "")
                for pattern in SENSITIVE_PARAM_PATTERNS:
                    if pattern.search(field_name):
                        self.risk_indicators.append({
                            "type": "sensitive_form_field",
                            "url": form.get("action", ""),
                            "field": field_name,
                            "risk": "high",
                            "detail": f"Form contains potentially sensitive field: {field_name}",
                        })
                        break

            for field in form.get("fields", []):
                field_name = field.get("name", "")
                for pattern in AI_PARAM_PATTERNS:
                    if pattern.search(field_name):
                        self.risk_indicators.append({
                            "type": "ai_input_field",
                            "url": form.get("action", ""),
                            "field": field_name,
                            "risk": "medium",
                            "detail": f"Form contains AI input field: {field_name}",
                        })
                        break

        for url, info in self.all_urls.items():
            status = info.get("status_code", 0)
            if status in (401, 403):
                self.risk_indicators.append({
                    "type": "restricted_area",
                    "url": url,
                    "status_code": status,
                    "risk": "medium",
                    "detail": f"Restricted area found (HTTP {status}): {url}",
                })
            if status == 500:
                self.risk_indicators.append({
                    "type": "server_error",
                    "url": url,
                    "status_code": status,
                    "risk": "medium",
                    "detail": f"Server error at: {url}",
                })

        admin_urls = self.classifications.get("admin_panel", [])
        for url in admin_urls:
            self.risk_indicators.append({
                "type": "admin_panel",
                "url": url,
                "risk": "high",
                "detail": f"Admin panel discovered: {url}",
            })

        auth_urls = self.classifications.get("auth_endpoint", [])
        for url in auth_urls:
            self.risk_indicators.append({
                "type": "auth_endpoint",
                "url": url,
                "risk": "medium",
                "detail": f"Authentication endpoint: {url}",
            })

        for graphql in self.all_graphql:
            if graphql.get("type") == "graphql_introspection":
                self.risk_indicators.append({
                    "type": "graphql_introspection",
                    "url": graphql.get("url", ""),
                    "risk": "medium",
                    "detail": f"GraphQL introspection enabled: {graphql.get('url', '')}",
                })

        for openapi in self.all_openapi:
            self.risk_indicators.append({
                "type": "openapi_doc_exposed",
                "url": openapi.get("url", ""),
                "risk": "low",
                "detail": f"OpenAPI documentation exposed: {openapi.get('url', '')} (v{openapi.get('version', 'unknown')})",
            })

    def _deduplicate(self) -> None:
        seen_urls = set()
        deduped_urls = {}
        for url, info in self.all_urls.items():
            normalized = self._normalize_url(url)
            if normalized not in seen_urls:
                seen_urls.add(normalized)
                deduped_urls[url] = info
        self.all_urls = deduped_urls

        seen_forms = set()
        deduped_forms = []
        for form in self.all_forms:
            key = (form.get("action", ""), form.get("method", ""), len(form.get("fields", [])))
            if key not in seen_forms:
                seen_forms.add(key)
                deduped_forms.append(form)
        self.all_forms = deduped_forms

        self.all_params = list(set(self.all_params))

        seen_js = set()
        deduped_js = []
        for js in self.all_js_files:
            if js not in seen_js:
                seen_js.add(js)
                deduped_js.append(js)
        self.all_js_files = deduped_js

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        query = urlencode(sorted(parse_qs(parsed.query).items()), doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, query, ""))

    def _build_summary(self) -> dict:
        return {
            "total_urls": len(self.all_urls),
            "total_forms": len(self.all_forms),
            "total_params": len(self.all_params),
            "total_js_files": len(self.all_js_files),
            "total_api_endpoints": len(self.all_apis),
            "total_graphql_endpoints": len(self.all_graphql),
            "total_openapi_docs": len(self.all_openapi),
            "total_risk_indicators": len(self.risk_indicators),
            "classification_counts": {
                cat: len(urls) for cat, urls in self.classifications.items()
            },
            "risk_counts": self._count_risks(),
        }

    def _count_risks(self) -> dict:
        counts = {"high": 0, "medium": 0, "low": 0}
        for indicator in self.risk_indicators:
            risk = indicator.get("risk", "low")
            if risk in counts:
                counts[risk] += 1
        return counts

    def _build_url_map(self) -> dict:
        url_map = {}
        for url, info in self.all_urls.items():
            classification = "other"
            for cat, urls in self.classifications.items():
                if url in urls:
                    classification = cat
                    break
            url_map[url] = {
                **info,
                "classification": classification,
            }
        return url_map

    def _build_form_map(self) -> list[dict]:
        form_map = []
        for form in self.all_forms:
            action = form.get("action", "")
            classification = "other"
            for cat, urls in self.classifications.items():
                if action in urls:
                    classification = cat
                    break
            form_map.append({
                **form,
                "classification": classification,
                "field_count": len(form.get("fields", [])),
                "sensitive_fields": self._find_sensitive_fields(form.get("fields", [])),
            })
        return form_map

    def _build_param_map(self) -> dict:
        param_map = {}
        for param in self.all_params:
            is_sensitive = False
            sensitivity_type = ""
            for pattern in SENSITIVE_PARAM_PATTERNS:
                if pattern.search(param):
                    is_sensitive = True
                    sensitivity_type = pattern.pattern
                    break
            param_map[param] = {
                "name": param,
                "is_sensitive": is_sensitive,
                "sensitivity_type": sensitivity_type,
            }
        return param_map

    def _build_api_map(self) -> dict:
        api_map = {}
        for url, info in self.all_apis.items():
            api_map[url] = {
                **info,
                "classification": "api_endpoint",
            }
        return api_map

    def _find_sensitive_fields(self, fields: list[dict]) -> list[str]:
        sensitive = []
        for field in fields:
            name = field.get("name", "")
            for pattern in SENSITIVE_PARAM_PATTERNS:
                if pattern.search(name):
                    sensitive.append(name)
                    break
        return sensitive

    def _extract_tech_stack(self, passive_results: dict | None = None) -> list[str]:
        techs = []
        if passive_results:
            techs.extend(passive_results.get("js_frameworks", []))
        for url, info in self.all_urls.items():
            technologies = info.get("technologies", [])
            techs.extend(technologies)
        return list(set(techs))

    def get_surface_map(self) -> dict:
        return self.surface_map

    def get_urls_by_classification(self, classification: str) -> list[str]:
        return self.classifications.get(classification, [])

    def get_risk_indicators(self, min_risk: str = "low") -> list[dict]:
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = risk_order.get(min_risk, 0)
        return [
            indicator for indicator in self.risk_indicators
            if risk_order.get(indicator.get("risk", "low"), 0) >= min_level
        ]

    def get_attack_surface_summary(self) -> dict:
        return {
            "total_endpoints": len(self.all_urls) + len(self.all_apis),
            "auth_endpoints": len(self.classifications.get("auth_endpoint", [])),
            "admin_panels": len(self.classifications.get("admin_panel", [])),
            "api_endpoints": len(self.all_apis),
            "graphql_endpoints": len(self.all_graphql),
            "file_uploads": len(self.classifications.get("file_upload", [])),
            "search_endpoints": len(self.classifications.get("search", [])),
            "forms_total": len(self.all_forms),
            "forms_with_sensitive_fields": sum(
                1 for f in self.all_forms
                if self._find_sensitive_fields(f.get("fields", []))
            ),
            "sensitive_params": sum(
                1 for p in self.all_params
                if any(pat.search(p) for pat in SENSITIVE_PARAM_PATTERNS)
            ),
            "risk_summary": self._count_risks(),
        }
