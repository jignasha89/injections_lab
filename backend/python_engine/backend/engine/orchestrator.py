import asyncio
import time
import traceback
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, parse_qs

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import async_session
from backend.models import Scan, Finding, AttackSurface, ScanStatus
from backend.api.websocket import (
    emit_scan_progress,
    emit_finding,
    emit_tool_output,
    emit_scan_completed,
    emit_scan_error,
    emit_crawl_update,
)
from backend.engine.crawler.deepcrawl import DeepCrawl
from backend.engine.crawler.surface_mapper import SurfaceMapper
from backend.engine.attack.payload_orchestrator import PayloadOrchestrator
from backend.engine.attack.executor import Executor
from backend.engine.analysis.response_analyzer import ResponseAnalyzer
from backend.engine.analysis.cvss_calculator import CVSSCalculator
from backend.reporting.mitigation_db import MitigationDB


PHASES = [
    "initializing",
    "crawling",
    "mapping",
    "planning",
    "executing",
    "analyzing",
    "storing",
    "completing",
]

PHASE_LABELS = {
    "initializing": "Initializing scan engine",
    "crawling": "Crawling target to discover attack surface",
    "mapping": "Mapping and unifying discovered endpoints",
    "planning": "Planning payloads for each injection point",
    "executing": "Executing attack payloads",
    "analyzing": "Analyzing responses for vulnerabilities",
    "storing": "Persisting findings to database",
    "completing": "Finalizing scan results",
}

PHASE_PERCENTAGE = {
    "initializing": 5,
    "crawling": 25,
    "mapping": 40,
    "planning": 50,
    "executing": 75,
    "analyzing": 90,
    "storing": 95,
    "completing": 100,
}


class ScanContext:
    def __init__(self, scan_id: str, config: dict):
        self.scan_id = scan_id
        self.config = config
        self.start_time: Optional[float] = None
        self.current_phase: str = "initializing"
        self.total_findings: int = 0
        self.urls_crawled: int = 0
        self.payloads_sent: int = 0
        self.endpoints_discovered: int = 0
        self.crawl_results: list = []
        self.attack_surface: dict = {}
        self.execution_plan = None
        self.scan_results: list = []
        self.findings: list = []
        self.errors: list = []

        self.deepcrawl: Optional[DeepCrawl] = None
        self.surface_mapper: Optional[SurfaceMapper] = None
        self.payload_orchestrator: Optional[PayloadOrchestrator] = None
        self.executor: Optional[Executor] = None
        self.response_analyzer: Optional[ResponseAnalyzer] = None
        self.cvss_calculator: Optional[CVSSCalculator] = None
        self.mitigation_db = MitigationDB()


async def _emit_progress(ctx: ScanContext, phase: str, detail: str = "", percentage: int = 0):
    ctx.current_phase = phase
    import backend.memory_store as _mem
    _mem.upsert_scan(ctx.scan_id, current_phase=phase, phase_percentage=percentage)
    payload = {
        "scan_id": ctx.scan_id,
        "phase": phase,
        "phase_label": PHASE_LABELS.get(phase, phase),
        "detail": detail,
        "percentage": percentage or PHASE_PERCENTAGE.get(phase, 0),
        "elapsed": round(time.time() - ctx.start_time, 1) if ctx.start_time else 0,
        "urls_crawled": ctx.urls_crawled,
        "endpoints_discovered": ctx.endpoints_discovered,
        "payloads_sent": ctx.payloads_sent,
        "findings_count": ctx.total_findings,
    }
    await emit_scan_progress(ctx.scan_id, payload)


async def _emit_tool(ctx: ScanContext, tool_name: str, message: str, level: str = "info"):
    await emit_tool_output(ctx.scan_id, tool_name, message, level)


async def _pause_check(ctx: ScanContext, pause_event: Optional[asyncio.Event]):
    if pause_event and not pause_event.is_set():
        await _emit_tool(ctx, "orchestrator", "Scan paused — waiting for resume signal", "warn")
        await pause_event.wait()
        await _emit_tool(ctx, "orchestrator", "Scan resumed", "info")


async def _stop_check(ctx: ScanContext, stop_event: Optional[asyncio.Event]) -> bool:
    if stop_event and stop_event.is_set():
        await _emit_tool(ctx, "orchestrator", "Scan abort requested", "warn")
        return True
    return False


async def _update_scan_status(session: Optional[AsyncSession], scan_id: str, status: ScanStatus, extra: dict = None):
    import uuid
    from backend import memory_store
    status_value = status.value if isinstance(status, ScanStatus) else str(status)
    values = {"status": status_value, "updated_at": datetime.now(timezone.utc)}
    if extra:
        values.update(extra)
    try:
        if session is not None:
            await session.execute(update(Scan).where(Scan.id == uuid.UUID(scan_id)).values(**values))
            await session.commit()
    except Exception:
        pass
    # mirror to memory so the API stays functional when PostgreSQL is down
    memory_store.upsert_scan(scan_id, status=status_value, **(extra or {}))


def _surface_to_endpoints(attack_surface: dict) -> list:
    """Flatten the SurfaceMapper output into a list of endpoint dicts for storage."""
    endpoints = []
    for url, info in (attack_surface.get("urls") or {}).items():
        params = [{"name": p, "type": "query"} for p in parse_qs(urlparse(url).query).keys()]
        endpoints.append({
            "url": url,
            "method": "GET",
            "parameters": params,
            "element_type": "url",
            "source_tool": info.get("source", "crawler"),
        })
    for form in attack_surface.get("forms", []) or []:
        endpoints.append({
            "url": form.get("action", ""),
            "method": form.get("method", "POST"),
            "parameters": [{"name": f.get("name", ""), "type": f.get("type", "text")}
                           for f in form.get("fields", [])],
            "element_type": "form",
            "source_tool": "crawler",
        })
    for url, info in (attack_surface.get("api_endpoints") or {}).items():
        endpoints.append({
            "url": url,
            "method": info.get("method", "POST"),
            "parameters": info.get("parameters", []),
            "element_type": "api",
            "source_tool": "api_discovery",
        })
    return endpoints


async def _store_attack_surface(session: AsyncSession, scan_id: str, attack_surface: dict):
    for ep in _surface_to_endpoints(attack_surface):
        record = AttackSurface(
            scan_id=scan_id,
            url=ep.get("url", ""),
            http_method=ep.get("method", "GET"),
            parameters_json=ep.get("parameters", []),
            element_type=ep.get("element_type", "url"),
            source_tool=ep.get("source_tool", "crawler"),
            created_at=datetime.now(timezone.utc),
        )
        session.add(record)
    await session.commit()


async def _store_findings(session: AsyncSession, scan_id: str, findings: list):
    for f in findings:
        record = Finding(
            scan_id=scan_id,
            title=f.get("title", "Untitled finding"),
            description=f.get("description", ""),
            severity=f.get("severity", "info"),
            cvss_score=f.get("cvss_score", 0.0),
            cvss_vector=f.get("cvss_vector", ""),
            confidence=f.get("confidence", "low"),
            vulnerability_id=f.get("vulnerability_id", ""),
            cwe_id=f.get("cwe_id", ""),
            injection_family=f.get("injection_family", ""),
            injection_subtype=f.get("injection_subtype", ""),
            affected_url=f.get("affected_url", ""),
            affected_parameter=f.get("affected_parameter", ""),
            payload=f.get("payload", ""),
            evidence_json=f.get("evidence", {}),
            mitigation_text=f.get("remediation", ""),
            verified=f.get("verified", False),
            created_at=datetime.now(timezone.utc),
        )
        session.add(record)
    await session.commit()


async def _phase_initialize(ctx: ScanContext):
    await _emit_progress(ctx, "initializing", "Setting up tool adapters")
    await _emit_tool(ctx, "orchestrator", f"Target: {ctx.config.get('target_url', 'N/A')}")
    await _emit_tool(ctx, "orchestrator", f"Scan ID: {ctx.scan_id}")

    ctx.deepcrawl = DeepCrawl()
    ctx.surface_mapper = SurfaceMapper()
    ctx.payload_orchestrator = PayloadOrchestrator()
    ctx.executor = Executor(
        scan_id=ctx.scan_id,
        config=ctx.config,
        concurrency=ctx.config.get("concurrency", 15),
        rate_limit=ctx.config.get("rate_limit", 30),
    )
    ctx.response_analyzer = ResponseAnalyzer()
    ctx.cvss_calculator = CVSSCalculator()

    await _emit_tool(ctx, "orchestrator", "All tool adapters initialized", "info")


async def _phase_crawl(ctx: ScanContext):
    await _emit_progress(ctx, "crawling", "Starting deep crawl of target")
    await _emit_tool(ctx, "deepcrawl", "Initiating deep crawl")

    try:
        run_results = await ctx.deepcrawl.run(
            target_url=ctx.config.get("target_url", ""),
            config=ctx.config,
            scan_id=ctx.scan_id,
        )
        ctx.crawl_results = run_results

        surface_map = run_results.get("phases", {}).get("surface_mapping", {})
        ctx.attack_surface = surface_map if isinstance(surface_map, dict) else {}

        ctx.urls_crawled = run_results.get("total_requests", 0)
        ctx.endpoints_discovered = (
            len(ctx.attack_surface.get("urls", {}))
            + len(ctx.attack_surface.get("forms", []))
            + len(ctx.attack_surface.get("api_endpoints", {}))
        )

        await _emit_tool(ctx, "deepcrawl", f"Crawl complete — {ctx.endpoints_discovered} endpoints discovered")
        await emit_crawl_update(ctx.scan_id, {
            "urls_found": ctx.urls_crawled,
            "urls_total": ctx.endpoints_discovered,
            "status": "complete",
        })
    except Exception as e:
        await _emit_tool(ctx, "deepcrawl", f"Crawl error: {str(e)}", "error")
        raise


async def _phase_map(ctx: ScanContext):
    await _emit_progress(ctx, "mapping", "Building unified attack surface")
    forms = len(ctx.attack_surface.get("forms", []) or [])
    params = len(ctx.attack_surface.get("parameters", {}) or {})
    await _emit_tool(
        ctx, "surface_mapper",
        f"Mapped {ctx.endpoints_discovered} endpoints, {forms} forms, {params} unique parameters",
    )


async def _phase_plan(ctx: ScanContext):
    await _emit_progress(ctx, "planning", "Generating payload execution plan")
    await _emit_tool(ctx, "payload_orchestrator", "Planning attack payloads")

    try:
        plan = ctx.payload_orchestrator.build_plan(
            scan_id=ctx.scan_id,
            attack_surface=ctx.attack_surface,
        )
        ctx.execution_plan = plan

        await _emit_tool(
            ctx, "payload_orchestrator",
            f"Planned {plan.total_payloads} payloads across {plan.total_families} families "
            f"for {len(plan.tasks)} element/family tasks",
        )
        if not plan.tasks:
            await _emit_tool(
                ctx, "payload_orchestrator",
                "No injectable elements found — nothing to test", "warn",
            )
    except Exception as e:
        await _emit_tool(ctx, "payload_orchestrator", f"Planning error: {str(e)}", "error")
        raise


async def _phase_execute(ctx: ScanContext, pause_event, stop_event):
    await _emit_progress(ctx, "executing", "Executing attack payloads")
    await _emit_tool(ctx, "executor", "Starting payload execution")

    try:
        if not ctx.execution_plan or not ctx.execution_plan.tasks:
            ctx.scan_results = []
            return

        results = await ctx.executor.execute_plan(ctx.execution_plan, pause_event=pause_event, stop_event=stop_event)
        ctx.scan_results = results

        ctx.payloads_sent = sum(getattr(r, "total_payloads", 0) for r in results)
        ctx.total_findings = sum(getattr(r, "anomalies_found", 0) for r in results)

        await _emit_progress(ctx, "executing", f"Sent {ctx.payloads_sent} payloads")
        await _emit_tool(ctx, "executor", f"Execution complete — {ctx.payloads_sent} payloads sent, {ctx.total_findings} anomalies")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        await _emit_tool(ctx, "executor", f"Execution error: {str(e)}", "error")
        raise


def _cvss_for(ctx: ScanContext, severity: str, element: dict, pattern_result=None) -> dict:
    try:
        cvss = ctx.cvss_calculator.calculate(severity, element, pattern_result)
        return {
            "score": cvss.get("base_score", 0.0),
            "vector": cvss.get("vector_string", ""),
            "severity": str(cvss.get("severity", severity)).lower(),
        }
    except Exception:
        return {"score": 0.0, "vector": "", "severity": severity}


async def _phase_analyze(ctx: ScanContext):
    await _emit_progress(ctx, "analyzing", "Analyzing responses for vulnerabilities")
    await _emit_tool(ctx, "response_analyzer", "Analyzing scan results")

    # Differential-only signals (length/time/status drift, plain
    # reflection) are family-agnostic: without family-specific
    # evidence they only warrant a low-confidence finding.
    GENERIC_SIGNALS = {
        "payload_reflected",
        "status_code_change",
        "body_length_significant_change",
        "response_time_spike",
        "baseline_error",
    }
    # Strength of family-specific evidence — used to pick the best
    # representative payload for each injection point.
    EVIDENCE_RANK = {
        "sql_error_disclosure": 10, "command_execution_evidence": 10,
        "template_injection_reflection": 9, "ssrf_cloud_metadata": 7,
        "open_redirect_confirmed": 7, "xxe_file_content": 8,
        "nosql_operator_detected": 8, "xss_reflection": 6,
        "html_injection_rendered": 6, "text_injection_reflected": 5,
        "ldap_error_disclosure": 8, "ldap_response_anomaly": 4,
        "crlf_header_injection": 7, "dom_xss_dataflow": 6,
    }

    def evidence_score(inj) -> int:
        reasons = getattr(inj, "anomaly_reasons", []) or []
        return max((EVIDENCE_RANK.get(r, 1) for r in reasons), default=0)

    try:
        # ── collect every anomalous payload ──
        candidates = []
        for task_result in ctx.scan_results:
            element = getattr(task_result, "element", {}) or {}
            family = getattr(task_result, "family", "unknown")
            for inj in getattr(task_result, "results", []):
                if getattr(inj, "anomaly_detected", False):
                    candidates.append((task_result, inj, element, family))

        # ── collapse to ONE finding per injection point (url + param +
        # family): keep the payload with the strongest evidence.
        # KEY FIX: Group by (url, param, family) only — NOT by subtype.
        # All subtypes of the same family on the same endpoint+param are
        # the same underlying vulnerability and must be merged.
        def norm_url(u: str) -> str:
            u = (u or "").strip()
            if "://" in u:
                scheme, rest = u.split("://", 1)
                u = scheme.lower() + "://" + rest
            return u.split("?", 1)[0].split("#", 1)[0].rstrip("/")

        # Each group collects ALL anomalous payloads for that injection point
        groups: dict = {}  # key -> list of (task_result, inj, element, family)
        for item in candidates:
            _tr, inj, element, family = item
            # Grouping by url, parameter_name, family ONLY (not subtype)
            key = (norm_url(element.get("url", "")), element.get("parameter_name", ""), family)
            groups.setdefault(key, []).append(item)

        await _emit_tool(
            ctx, "response_analyzer",
            f"{len(candidates)} raw anomalies -> {len(groups)} unique injection points",
        )

        sem = asyncio.Semaphore(10)

        async def analyze_group(key, items):
            """Analyze a group of anomalies for a single injection point.
            Returns one consolidated finding with evidence from the best payload
            and a summary of all successful subtypes/payloads."""
            # Pick the best payload (highest evidence score)
            best_item = max(items, key=lambda it: (
                evidence_score(it[1]),
                len(getattr(it[1], "anomaly_reasons", []) or []),
            ))
            task_result, inj, element, family = best_item
            url = element.get("url", "")
            param = element.get("parameter_name", "")
            http_method = element.get("method", element.get("http_method", "GET"))
            param_location = element.get("parameter_location", element.get("element_type", "query"))
            subtype = getattr(inj, "subtype", "")
            reasons = list(getattr(inj, "anomaly_reasons", []) or [])
            has_specific_evidence = any(r not in GENERIC_SIGNALS for r in reasons)

            # Collect all unique subtypes and successful payloads for this group
            successful_tests = []
            seen_subtypes = set()
            for _tr_i, inj_i, _el_i, _fam_i in items:
                st = getattr(inj_i, "subtype", "") or "generic"
                payload_str = str(getattr(inj_i, "payload_string", ""))[:300]
                inj_reasons = list(getattr(inj_i, "anomaly_reasons", []) or [])
                if payload_str:
                    successful_tests.append({
                        "subtype": st,
                        "payload": payload_str,
                        "reasons": inj_reasons,
                        "status_code": getattr(inj_i, "status_code", 0),
                        "response_time": round(getattr(inj_i, "response_time", 0), 3),
                    })
                seen_subtypes.add(st)
            # Cap to 5 most relevant tests to avoid bloat
            successful_tests.sort(key=lambda t: (
                max((EVIDENCE_RANK.get(r, 0) for r in t["reasons"]), default=0)
            ), reverse=True)
            successful_tests = successful_tests[:5]

            verified = False
            confidence = "medium"
            cvss = None

            async with sem:
                try:
                    baseline_obj = getattr(task_result, "baseline", None)
                    if baseline_obj is not None:
                        baseline_dict = {
                            "status_code": getattr(baseline_obj, "status_code", 0) or 0,
                            "body": (getattr(baseline_obj, "body", "") or "")[:200_000],
                            "headers": getattr(baseline_obj, "headers", {}) or {},
                            "response_time": getattr(baseline_obj, "response_time", 0) or 0,
                        }
                    else:
                        baseline_dict = {
                            "status_code": 200, "body": "", "headers": {}, "response_time": 0,
                        }
                    payload_dict = {
                        "status_code": getattr(inj, "status_code", 0),
                        "body": (getattr(inj, "body", "") or "")[:200_000],
                        "headers": getattr(inj, "headers", {}) or {},
                        "response_time": getattr(inj, "response_time", 0),
                    }
                    try:
                        analysis = await asyncio.wait_for(
                            ctx.response_analyzer.analyze(
                                baseline_response=baseline_dict,
                                payload_response=payload_dict,
                                payload=getattr(inj, "payload_string", ""),
                                element=element,
                            ),
                            timeout=45,
                        )
                    except asyncio.TimeoutError:
                        analysis = None
                    except Exception:
                        analysis = None
                    if analysis and analysis.get("severity"):
                        verified = bool(analysis.get("verification", {}).get("verified"))
                        confidence = analysis.get("confidence", {}).get("level", "medium")
                        cvss = analysis.get("cvss")
                except Exception:
                    pass

            severity_map = {
                "sqli": "critical", "cmdi": "critical", "ssti": "critical",
                "code_injection": "critical", "nosql": "high", "xxe": "high",
                "xss": "high", "ssrf": "high", "path_traversal": "high",
                "xpath": "high", "open_redirect": "medium", "crlf": "medium",
                "header_injection": "medium", "email_injection": "medium",
                "formula_injection": "medium",
                "htmli": "medium", "texti": "low", "ldapi": "critical",
            }
            severity = severity_map.get(family, "medium")
            family_specific_signals = {
                "html_injection_rendered", "text_injection_reflected",
                "crlf_header_injection", "ldap_error_disclosure",
                "ldap_response_anomaly", "dom_xss_dataflow",
                "sql_error_disclosure", "command_execution_evidence",
                "template_injection_reflection", "xss_reflection",
                "ssrf_cloud_metadata", "open_redirect_confirmed",
                "xxe_file_content", "nosql_operator_detected",
            }
            has_family_specific = any(r in family_specific_signals for r in reasons)
            if not has_specific_evidence and not verified and not has_family_specific:
                severity = "low"
                confidence = "low"

            if cvss:
                cvss_score = cvss.get("base_score", 0.0)
                cvss_vector = cvss.get("vector_string", "")
            else:
                c = _cvss_for(ctx, severity, element)
                cvss_score = c["score"]
                cvss_vector = c["vector"]

            # Build human-readable title — use best subtype
            best_subtype = subtype or "generic"
            # If multiple subtypes detected, note it
            subtypes_list = sorted(seen_subtypes)
            subtypes_str = ", ".join(subtypes_list) if subtypes_list else best_subtype

            return {
                "title": f"{family.upper()} in {param or 'parameter'} at {url}",
                "description": (
                    f"Potential {family} vulnerability detected. "
                    f"Subtypes tested: {subtypes_str}. "
                    f"Detection signals: {', '.join(reasons or ['anomaly'])}."
                ),
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "confidence": confidence,
                "verified": verified,
                "injection_family": family,
                "injection_subtype": best_subtype,
                "affected_url": url,
                "affected_parameter": param,
                "http_method": http_method,
                "parameter_location": param_location,
                "payload": str(getattr(inj, "payload_string", ""))[:500],
                "remediation": ctx.mitigation_db.get_mitigation(subtype or family).get("remediation", ""),
                "evidence": {
                    "reasons": reasons,
                    "status_code": getattr(inj, "status_code", 0),
                    "body_length": getattr(inj, "body_length", 0),
                    "response_time": round(getattr(inj, "response_time", 0), 3),
                    "http_method": http_method,
                    "parameter_location": param_location,
                    "tested_value": str(getattr(inj, "payload_string", ""))[:500],
                    "successful_tests": successful_tests,
                    "subtypes_detected": subtypes_list,
                    "total_anomalies_in_group": len(items),
                },
                "cwe_id": ctx.mitigation_db.get_cwe(family),
            }

        # analyze all injection points concurrently (10 at a time)
        findings = []
        suppressed = 0
        if groups:
            results = await asyncio.gather(
                *[analyze_group(key, items) for key, items in groups.items()],
                return_exceptions=True,
            )
            for f in results:
                if not isinstance(f, dict):
                    continue
                f_reasons = (f.get("evidence") or {}).get("reasons", [])
                if (f.get("severity") == "low"
                        and f.get("confidence") == "low"
                        and not f.get("verified")
                        and not f_reasons):
                    suppressed += 1
                    continue
                findings.append(f)

        if suppressed:
            await _emit_tool(
                ctx, "response_analyzer",
                f"{suppressed} low-confidence anomalies suppressed (weak evidence only)",
            )

        ctx.findings = findings
        ctx.total_findings = len(findings)

        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        await _emit_tool(
            ctx, "response_analyzer",
            f"Analysis complete - {ctx.total_findings} unique findings ({severity_counts})",
        )

        for finding in findings:
            await emit_finding(ctx.scan_id, {
                "title": finding.get("title", ""),
                "severity": finding.get("severity", "info"),
                "cvss_score": finding.get("cvss_score", 0.0),
                "affected_url": finding.get("affected_url", ""),
                "affected_parameter": finding.get("affected_parameter", ""),
                "injection_family": finding.get("injection_family", ""),
                "injection_subtype": finding.get("injection_subtype", ""),
                "confidence": finding.get("confidence", "low"),
                "verified": finding.get("verified", False),
                "payload": finding.get("payload", ""),
                "http_method": finding.get("http_method", ""),
                "parameter_location": finding.get("parameter_location", ""),
            })
    except Exception as e:
        await _emit_tool(ctx, "response_analyzer", f"Analysis error: {str(e)}", "error")
        raise


async def _phase_store(ctx: ScanContext, session: Optional[AsyncSession]):
    await _emit_progress(ctx, "storing", "Saving results to database")
    from backend import memory_store
    await _emit_tool(ctx, "orchestrator", "Persisting findings and attack surface")

    try:
        if session is not None:
            await _store_attack_surface(session, ctx.scan_id, ctx.attack_surface)
            await _store_findings(session, ctx.scan_id, ctx.findings)
    except Exception as e:
        await _emit_tool(
            ctx, "orchestrator",
            f"Database persistence failed — keeping results in memory: {e}", "warn",
        )

    try:
        memory_store.set_surface(ctx.scan_id, _surface_to_endpoints(ctx.attack_surface))
        memory_store.add_findings(ctx.scan_id, ctx.findings)
    except Exception:
        pass

    await _emit_tool(ctx, "orchestrator", f"Stored {len(ctx.findings)} findings", "info")

    scan_duration = round(time.time() - ctx.start_time, 1) if ctx.start_time else 0
    await _update_scan_status(session, ctx.scan_id, ScanStatus.COMPLETED, {
        "completed_at": datetime.now(timezone.utc),
        "current_phase": "completing",
        "findings_count": ctx.total_findings,
        "urls_crawled": ctx.urls_crawled,
        "endpoints_discovered": ctx.endpoints_discovered,
        "payloads_sent": ctx.payloads_sent,
        "scan_duration": scan_duration,
        "errors_count": len(ctx.errors),
    })
    await _emit_tool(ctx, "orchestrator", f"Results saved — {ctx.total_findings} findings persisted")


async def _phase_complete(ctx: ScanContext):
    await _emit_progress(ctx, "completing", "Finalizing scan")
    scan_duration = round(time.time() - ctx.start_time, 1) if ctx.start_time else 0

    await emit_scan_completed(
        ctx.scan_id,
        ctx.total_findings,
        scan_duration,
        {"total": ctx.total_findings, "errors": len(ctx.errors)},
    )

    await _emit_tool(
        ctx,
        "orchestrator",
        f"Scan completed in {scan_duration}s — {ctx.total_findings} findings",
    )


async def _cleanup_tools(ctx: ScanContext):
    for tool in (ctx.executor, ctx.deepcrawl, ctx.response_analyzer):
        if tool and hasattr(tool, "close"):
            try:
                await tool.close()
            except Exception:
                pass


async def run_scan(scan_id: str, config: dict, pause_event=None, stop_event=None):
    import uuid
    from backend import memory_store

    ctx = ScanContext(scan_id, config)
    ctx.start_time = time.time()

    # Prefer PostgreSQL; fall back to the in-memory store when it is
    # unreachable so scans still run and results are still served.
    session = None
    db_mode = False
    try:
        session = async_session()
        scan_row = await session.get(Scan, uuid.UUID(scan_id))
        db_mode = scan_row is not None
    except Exception:
        db_mode = False

    if not db_mode:
        if session is not None:
            try:
                await session.close()
            except Exception:
                pass
            session = None
        if memory_store.get_scan(scan_id) is None:
            await emit_scan_error(scan_id, f"Scan {scan_id} not found")
            return
        await _emit_tool(
            ctx, "orchestrator",
            "PostgreSQL unavailable — running in in-memory mode (results not persisted after restart)", "warn",
        )

    try:
        await _update_scan_status(session, scan_id, ScanStatus.RUNNING, {"current_phase": "initializing"})

        await _phase_initialize(ctx)
        for step in (
            ("crawl", lambda: _phase_crawl(ctx)),
            ("map", lambda: _phase_map(ctx)),
            ("plan", lambda: _phase_plan(ctx)),
            ("execute", lambda: _phase_execute(ctx, pause_event, stop_event)),
            ("analyze", lambda: _phase_analyze(ctx)),
            ("store", lambda: _phase_store(ctx, session)),
            ("complete", lambda: _phase_complete(ctx)),
        ):
            if await _stop_check(ctx, stop_event):
                # Persist whatever findings were collected before stopping
                if ctx.findings:
                    try:
                        from backend import memory_store as _ms
                        _ms.add_findings(scan_id, ctx.findings)
                        if session is not None:
                            await _store_findings(session, scan_id, ctx.findings)
                    except Exception:
                        pass
                await _update_scan_status(session, scan_id, ScanStatus.STOPPED, {
                    "completed_at": datetime.now(timezone.utc),
                    "current_phase": "stopped",
                    "findings_count": ctx.total_findings,
                    "urls_crawled": ctx.urls_crawled,
                    "endpoints_discovered": ctx.endpoints_discovered,
                    "payloads_sent": ctx.payloads_sent,
                    "scan_duration": round(time.time() - ctx.start_time, 1) if ctx.start_time else 0,
                })
                return
            await step[1]()

    except asyncio.CancelledError:
        try:
            await _emit_tool(ctx, "orchestrator", "Scan stopped", "warn")
            await _update_scan_status(session, scan_id, ScanStatus.STOPPED, {
                "completed_at": datetime.now(timezone.utc),
            })
        except Exception:
            pass
        raise

    except Exception as e:
        tb = traceback.format_exc()
        await _emit_tool(ctx, "orchestrator", f"Fatal error: {str(e)}", "error")
        await _emit_tool(ctx, "orchestrator", tb, "error")

        try:
            await _update_scan_status(session, scan_id, ScanStatus.FAILED, {
                "error_message": str(e),
                "completed_at": datetime.now(timezone.utc),
            })
        except Exception:
            pass

        await emit_scan_error(scan_id, str(e))

    finally:
        await _cleanup_tools(ctx)
        if session is not None:
            try:
                await session.close()
            except Exception:
                pass
