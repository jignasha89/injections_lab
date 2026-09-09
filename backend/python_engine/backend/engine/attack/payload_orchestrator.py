import logging
import random
from typing import Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

from backend.engine.attack.payload_db import PayloadDB, ALL_FAMILIES
from backend.engine.attack.mutator import Mutator

logger = logging.getLogger(__name__)

ELEMENT_TO_FAMILY_MAP: dict[str, dict[str, list[str]]] = {
    "login_form": {
        "primary": ["sqli", "xss", "htmli", "log_injection", "null_byte", "unicode_injection"],
        "secondary": ["cmdi", "ssti", "ldapi", "texti", "object_injection"],
    },
    "search_field": {
        "primary": ["xss", "sqli", "htmli", "texti", "log_injection", "parameter_pollution", "regex_injection"],
        "secondary": ["cmdi", "ssti", "path_traversal", "unicode_injection"],
    },
    "url_query_parameter": {
        "primary": ["sqli", "xss", "path_traversal", "htmli", "texti", "log_injection", "parameter_pollution"],
        "secondary": ["open_redirect", "ssrf", "header_injection", "ssti", "cmdi", "crlf"],
    },
    "url_path_parameter": {
        "primary": ["path_traversal", "sqli", "htmli", "log_injection", "parameter_pollution", "null_byte"],
        "secondary": ["xss", "cmdi"],
    },
    "post_body_json": {
        "primary": ["nosql", "header_injection", "sqli", "object_injection", "log_injection", "parameter_pollution", "modern_injection"],
        "secondary": ["code_injection", "xss", "htmli", "texti"],
    },
    "http_headers": {
        "primary": ["xss", "crlf", "header_injection", "texti", "log_injection"],
        "secondary": ["sqli", "email_injection", "ssrf"],
    },
    "host_header": {
        "primary": ["header_injection", "ssrf", "log_injection"],
        "secondary": ["open_redirect", "texti"],
    },
    "cookie_parameters": {
        "primary": ["sqli", "xss", "log_injection"],
        "secondary": ["header_injection", "htmli"],
    },
    "file_upload": {
        "primary": ["code_injection", "path_traversal", "null_byte", "pdf_injection"],
        "secondary": ["xxe", "sqli", "ssi_injection"],
    },
    "rest_api": {
        "primary": ["sqli", "header_injection", "nosql", "xss", "object_injection", "log_injection", "parameter_pollution", "modern_injection"],
        "secondary": ["cmdi", "ssti", "htmli", "ssrf", "xml_injection", "prompt_injection"],
    },
    "graphql": {
        "primary": ["sqli", "nosql", "log_injection", "modern_injection"],
        "secondary": ["xss", "ssti"],
    },
    "soap_xml": {
        "primary": ["xxe", "xpath", "xml_injection", "log_injection"],
        "secondary": ["sqli", "ssti"],
    },
    "email_fields": {
        "primary": ["email_injection", "xss", "texti", "protocol_injection", "log_injection"],
        "secondary": ["cmdi", "htmli"],
    },
    "csv_report_export": {
        "primary": ["formula_injection", "xss"],
        "secondary": ["texti"],
    },
    "js_rendered": {
        "primary": ["xss", "code_injection"],
        "secondary": ["htmli"],
    },
    "ldap_login": {
        "primary": ["ldapi", "sqli", "log_injection"],
        "secondary": ["xss", "htmli"],
    },
    "template_output": {
        "primary": ["ssti", "xss", "htmli", "object_injection", "log_injection", "css_injection", "ssi_injection"],
        "secondary": ["code_injection", "texti"],
    },
    "redirect_params": {
        "primary": ["open_redirect", "ssrf", "log_injection", "modern_injection"],
        "secondary": ["xss", "htmli"],
    },
    "websocket": {
        "primary": ["xss", "cmdi", "log_injection"],
        "secondary": ["sqli"],
    },
    "comment_field": {
        "primary": ["xss", "htmli", "texti", "log_injection"],
        "secondary": ["sqli", "ssti"],
    },
    "message_field": {
        "primary": ["xss", "htmli", "texti", "log_injection", "prompt_injection"],
        "secondary": ["sqli", "cmdi"],
    },
    "ai_input": {
        "primary": ["prompt_injection"],
        "secondary": ["xss", "sqli", "cmdi", "ssti", "log_injection", "texti"],
    },
    "oauth_endpoint": {
        "primary": ["modern_injection", "open_redirect", "ssrf"],
        "secondary": ["xss", "log_injection"],
    },
}

TECHNOLOGY_BONUS: dict[str, float] = {
    "php": 2.0,
    "java": 2.0,
    "python": 1.5,
    "nodejs": 1.5,
    "ruby": 1.5,
    "go": 1.0,
    "mysql": 2.0,
    "postgresql": 2.0,
    "mssql": 2.0,
    "mongodb": 2.0,
    "redis": 1.5,
    "jinja2": 2.5,
    "twig": 2.5,
    "freemarker": 2.5,
    "velocity": 2.5,
    "smarty": 2.5,
    "flask": 2.0,
    "django": 2.0,
    "laravel": 2.0,
    "spring": 2.0,
    "express": 2.0,
    "tomcat": 2.0,
    "apache": 1.5,
    "nginx": 1.5,
    "iis": 1.5,
}

CONTEXT_BONUS: dict[str, float] = {
    "html": 1.5,
    "attribute": 1.5,
    "javascript_string": 2.0,
    "url_fragment": 2.0,
    "url": 1.0,
    "json": 1.5,
    "xml": 2.0,
    "template": 2.5,
    "string": 1.0,
    "header": 1.5,
    "cookie": 1.5,
}

BASE_SCORE = 5.0
MIN_THRESHOLD = 2.0
MAX_FAMILIES_PER_ELEMENT = 8


@dataclass
class ScoredFamily:
    family: str
    score: float
    primary: bool
    payload_count: int = 0


@dataclass
class ExecutionTask:
    element: dict
    family: str
    payloads: list[dict]
    score: float
    primary: bool


@dataclass
class ExecutionPlan:
    scan_id: str
    tasks: list[ExecutionTask] = field(default_factory=list)
    total_families: int = 0
    total_payloads: int = 0


class PayloadOrchestrator:
    def __init__(
        self,
        payload_db: Optional[PayloadDB] = None,
        mutator: Optional[Mutator] = None,
    ):
        self.payload_db = payload_db or PayloadDB()
        self.mutator = mutator or Mutator()
        self._historical_findings: dict[str, int] = {}

    def set_historical_findings(self, findings: list[dict]):
        self._historical_findings = {}
        for f in findings:
            family = f.get("injection_family", "")
            if family:
                self._historical_findings[family] = (
                    self._historical_findings.get(family, 0) + 1
                )

    def _detect_element_type(self, element: dict) -> str:
        element_type = element.get("element_type", "")
        if element_type and element_type in ELEMENT_TO_FAMILY_MAP:
            return element_type

        url = element.get("url", "")
        params = element.get("parameters_json", [])
        forms = element.get("form_fields_json", [])
        headers = element.get("headers_json", {})
        classification = element.get("classification", "")
        param_name = element.get("parameter_name", "").lower()
        param_type = element.get("parameter_type", "").lower()

        if classification == "auth_endpoint" or "login" in url.lower():
            return "login_form"
        if classification == "search" or "search" in url.lower() or param_name in ("q", "query", "search", "keyword", "term", "s"):
            return "search_field"
        if classification == "file_upload" or param_type == "file":
            return "file_upload"
        if classification == "admin_panel":
            return "rest_api"

        # Classify AI inputs
        if param_name in ("prompt", "query", "message", "input", "instruction", "context", "user_message", "q"):
            # if we see 'search' it's probably search, but otherwise could be AI
            if classification != "search" and "search" not in url.lower():
                return "ai_input"

        # Classify OAuth endpoints
        if any(oauth_term in url.lower() for oauth_term in ("oauth", "authorize", "token", "openid", "callback")):
            return "oauth_endpoint"

        # Classify comment/message/textarea fields
        if param_name in ("comment", "comments", "message", "msg", "body", "content",
                          "text", "description", "note", "notes", "feedback", "review"):
            if any(kw in param_name for kw in ("comment", "review", "feedback")):
                return "comment_field"
            return "message_field"
        if param_type == "textarea":
            return "message_field"

        if "graphql" in url.lower():
            return "graphql"
        if ".xml" in url.lower() or "soap" in url.lower():
            return "soap_xml"
        if "ws://" in url or "wss://" in url:
            return "websocket"
        if "export" in url.lower() or "report" in url.lower() or "csv" in url.lower():
            return "csv_report_export"
        if "redirect" in url.lower() or param_name in ("redirect", "url", "next", "return", "returnurl", "goto"):
            return "redirect_params"
        if "template" in url.lower() or param_name in ("template", "tpl", "theme"):
            return "template_output"

        if forms:
            return "login_form"
        if headers:
            header_keys = [k.lower() for k in headers.keys()]
            if "host" in header_keys:
                return "host_header"
            return "http_headers"
        if params:
            return "url_query_parameter"

        return "url_query_parameter"

    def _get_technologies(self, element: dict) -> list[str]:
        tech = element.get("technology_json", {})
        if isinstance(tech, dict):
            return tech.get("technologies", tech.get("stack", []))
        if isinstance(tech, list):
            return tech
        return []

    def _get_context(self, element: dict) -> str:
        context = element.get("context", "")
        if context:
            return context
        element_type = self._detect_element_type(element)
        context_map = {
            "login_form": "string",
            "search_field": "string",
            "url_query_parameter": "string",
            "url_path_parameter": "string",
            "post_body_json": "json",
            "http_headers": "header",
            "host_header": "header",
            "cookie_parameters": "cookie",
            "file_upload": "string",
            "rest_api": "json",
            "graphql": "json",
            "soap_xml": "xml",
            "email_fields": "string",
            "csv_report_export": "string",
            "js_rendered": "html",
            "ldap_login": "string",
            "template_output": "template",
            "redirect_params": "url",
            "websocket": "string",
            "comment_field": "html",
            "message_field": "html",
            "ai_input": "string",
            "oauth_endpoint": "url",
        }
        return context_map.get(element_type, "string")

    def _score_family(
        self,
        family: str,
        element_type: str,
        context: str,
        technologies: list[str],
        is_primary: bool,
    ) -> float:
        score = BASE_SCORE

        if is_primary:
            score += 2.0
        else:
            score += 0.0

        for tech in technologies:
            tech_lower = tech.lower()
            if tech_lower in TECHNOLOGY_BONUS:
                score += TECHNOLOGY_BONUS[tech_lower]

        if context in CONTEXT_BONUS:
            score += CONTEXT_BONUS[context]

        historical_count = self._historical_findings.get(family, 0)
        score += min(historical_count * 0.5, 3.0)

        payloads = self.payload_db.get_payloads_by_family(family)
        if not payloads:
            score -= 5.0
        elif len(payloads) < 3:
            score -= 1.0

        if context == "json" and family in ("sqli", "xpath", "path_traversal"):
            score -= 2.0
        if context == "html" and family in ("sqli", "cmdi", "ssrf", "path_traversal"):
            score -= 1.5
        if context == "xml" and family in ("xss", "cmdi"):
            score -= 1.5
        if context == "template" and family not in ("ssti", "xss"):
            score -= 2.0

        return round(score, 2)

    def plan_element(self, element: dict) -> list[ScoredFamily]:
        element_type = self._detect_element_type(element)
        context = self._get_context(element)
        technologies = self._get_technologies(element)

        mapping = ELEMENT_TO_FAMILY_MAP.get(element_type, {})
        primary_families = mapping.get("primary", [])
        secondary_families = mapping.get("secondary", [])

        scored = []
        for family in primary_families:
            s = self._score_family(
                family, element_type, context, technologies, True
            )
            payloads = self.payload_db.get_payloads_by_family(family)
            scored.append(ScoredFamily(
                family=family,
                score=s,
                primary=True,
                payload_count=len(payloads),
            ))

        for family in secondary_families:
            s = self._score_family(
                family, element_type, context, technologies, False
            )
            payloads = self.payload_db.get_payloads_by_family(family)
            scored.append(ScoredFamily(
                family=family,
                score=s,
                primary=False,
                payload_count=len(payloads),
            ))

        scored.sort(key=lambda x: (-x.score, -x.payload_count))

        selected = []
        for sf in scored:
            if sf.score < MIN_THRESHOLD:
                continue
            selected.append(sf)
            if len(selected) >= MAX_FAMILIES_PER_ELEMENT:
                break

        return selected

    def build_plan(
        self,
        scan_id: str,
        attack_surface: dict,
    ) -> ExecutionPlan:
        plan = ExecutionPlan(scan_id=scan_id)

        elements = self._extract_elements(attack_surface)

        for element in elements:
            scored_families = self.plan_element(element)
            for sf in scored_families:
                # Skip reflection-based families on password-type fields —
                # passwords are hashed, never reflected; testing wastes requests
                # and generates false positives. Skip only for URL/query params,
                # not for form fields (where POST payloads are tested).
                param_type = str(element.get("parameter_type", "")).lower()
                param_name = str(element.get("parameter_name", "")).lower()
                skip_password_fields = (
                    sf.family in ("xss", "path_traversal", "open_redirect")
                    and element.get("element_type", "") not in ("login_form", "search_field")
                    and (
                        param_type == "password"
                        or "pass" in param_name
                        or "pwd" in param_name
                        or "secret" in param_name
                        or "token" in param_name
                        or "csrf" in param_name
                    )
                )
                if skip_password_fields:
                    continue

                payloads = self.payload_db.get_payloads_by_family(sf.family)
                context = self._get_context(element)
                filtered = [
                    p for p in payloads
                    if p.get("context") == context
                    or not p.get("context")
                ]
                if not filtered:
                    filtered = payloads[:10]
                # cap at 20 payloads per element×family for thorough coverage
                filtered = filtered[:20]

                task = ExecutionTask(
                    element=element,
                    family=sf.family,
                    payloads=filtered,
                    score=sf.score,
                    primary=sf.primary,
                )
                plan.tasks.append(task)
                plan.total_payloads += len(filtered)

        plan.tasks.sort(
            key=lambda t: (-t.score, -t.primary)
        )
        plan.total_families = len(set(t.family for t in plan.tasks))

        logger.info(
            f"Execution plan for {scan_id}: {len(plan.tasks)} tasks, "
            f"{plan.total_families} families, {plan.total_payloads} payloads"
        )
        return plan

    def _extract_elements(self, attack_surface: dict) -> list[dict]:
        elements = []

        # ── URLs with query parameters ──
        for url, info in attack_surface.get("urls", {}).items():
            classification = info.get("classification", "")
            if classification in ("static_resource",):
                continue

            # Extract query-string params from the URL itself
            parsed = urlparse(url)
            qs_params = parse_qs(parsed.query, keep_blank_values=True)
            for param_name in qs_params:
                param_type = "query"
                element_type = "url_query_parameter"
                # Classify the element based on context
                if classification == "auth_endpoint" or "login" in url.lower():
                    element_type = "login_form"
                elif classification == "search":
                    element_type = "search_field"
                elif classification == "api_endpoint" or "/api/" in url.lower():
                    element_type = "rest_api"

                elements.append({
                    "url": url,
                    "element_type": element_type,
                    "parameter_name": param_name,
                    "parameter_type": param_type,
                    "technology_json": info.get("technologies", {}),
                    "classification": classification,
                    "context": "string",
                })

            # Also use any 'parameters' key the surface mapper may have attached
            for param in info.get("parameters", []):
                elements.append({
                    "url": url,
                    "element_type": "url_query_parameter",
                    "parameter_name": param.get("name", ""),
                    "parameter_type": param.get("type", "query"),
                    "technology_json": info.get("technologies", {}),
                    "classification": classification,
                    "context": "string",
                })

        for form in attack_surface.get("forms", []):
            action = form.get("action", "")
            method = form.get("method", "POST").upper()
            classification = form.get("classification", "")
            
            # Collect ALL form fields for POST body inclusion
            all_fields = [
                {"name": f.get("name", ""), "value": f.get("value", ""), "type": f.get("type", "text")}
                for f in form.get("fields", [])
            ]
            
            for field in form.get("fields", []):
                field_type = field.get("type", "text").lower()
                element_type = "post_body_json" if field_type == "hidden" else "login_form"
                if "search" in action.lower() or "search" in classification.lower():
                    element_type = "search_field"
                if "upload" in action.lower() or field_type == "file":
                    element_type = "file_upload"
                if "email" in field.get("name", "").lower():
                    element_type = "email_fields"

                elements.append({
                    "url": action,
                    "element_type": element_type,
                    "parameter_name": field.get("name", ""),
                    "parameter_type": field.get("type", "text"),
                    "technology_json": form.get("technologies", {}),
                    "classification": classification,
                    "http_method": method,
                    "context": "string",
                    "form_fields": all_fields,  # ALL fields for POST body
                })

        for url, info in attack_surface.get("api_endpoints", {}).items():
            content_type = info.get("content_type", "json")
            for param in info.get("parameters", []):
                elements.append({
                    "url": url,
                    "element_type": "rest_api",
                    "parameter_name": param.get("name", ""),
                    "parameter_type": param.get("type", "body"),
                    "technology_json": info.get("technologies", {}),
                    "classification": "api_endpoint",
                    "http_method": info.get("method", "POST"),
                    "context": "json" if content_type == "json" else "string",
                })
            # If no per-endpoint params, parse URL query string
            if not info.get("parameters"):
                parsed = urlparse(url)
                for pn in parse_qs(parsed.query, keep_blank_values=True):
                    elements.append({
                        "url": url,
                        "element_type": "rest_api",
                        "parameter_name": pn,
                        "parameter_type": "query",
                        "technology_json": info.get("technologies", {}),
                        "classification": "api_endpoint",
                        "http_method": info.get("method", "POST"),
                        "context": "string",
                    })

        for gql in attack_surface.get("graphql_endpoints", []):
            elements.append({
                "url": gql.get("url", ""),
                "element_type": "graphql",
                "parameter_name": "query",
                "parameter_type": "body",
                "technology_json": {},
                "classification": "graphql",
                "http_method": "POST",
                "context": "json",
            })

        tech_stack = attack_surface.get("technology_stack", [])
        if tech_stack:
            for el in elements:
                existing = el.get("technology_json", {})
                if isinstance(existing, dict):
                    existing.setdefault("technologies", tech_stack)
                else:
                    el["technology_json"] = {"technologies": tech_stack}

        return elements
