import re
import time
import asyncio
import logging
import statistics
import math
import json
import uuid
from typing import Dict, List, Optional, Any, Tuple
from .differential import DifferentialAnalyzer
from .pattern_matcher import PatternMatcher
from .behavioral import BehavioralAnalyzer
from .verifier import PayloadVerifier
from .confidence_scorer import ConfidenceScorer
from .cvss_calculator import CVSSCalculator

logger = logging.getLogger(__name__)


class ResponseAnalyzer:
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.differential = DifferentialAnalyzer()
        self.pattern_matcher = PatternMatcher()
        self.behavioral = BehavioralAnalyzer()
        self.verifier = PayloadVerifier(http_client)
        self.confidence_scorer = ConfidenceScorer()
        self.cvss_calculator = CVSSCalculator()
        self.analysis_results: List[Dict[str, Any]] = []
        self.payload_history: Dict[str, List[Dict[str, Any]]] = {}

    async def analyze(
        self,
        baseline_response: Dict[str, Any],
        payload_response: Dict[str, Any],
        payload: str,
        element: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        analysis_id = str(uuid.uuid4())
        start_time = time.time()
        logger.info(f"Starting analysis {analysis_id} for payload: {payload[:50]}...")

        stage1_result = await self._stage1_differential_analysis(
            baseline_response, payload_response, payload, element
        )
        if not stage1_result:
            logger.info(f"Analysis {analysis_id}: Stage 1 - no significant deviation")
            return None

        stage2_result = await self._stage2_pattern_matching(
            payload_response, payload, element
        )

        stage3_result = await self._stage3_behavioral_analysis(
            baseline_response, payload_response, payload, element
        )

        stage4_result = await self._stage4_verification(
            payload, element, stage2_result, stage3_result
        )

        stage5_result = await self._stage5_confidence_scoring(
            stage1_result, stage2_result, stage3_result, stage4_result
        )

        stage6_result = await self._stage6_evidence_correlation(
            stage1_result, stage2_result, stage3_result, stage4_result, stage5_result
        )

        elapsed = time.time() - start_time
        finding = {
            "id": analysis_id,
            "payload": payload,
            "element": element,
            "timestamp": time.time(),
            "elapsed_seconds": round(elapsed, 3),
            "differential": stage1_result,
            "patterns": stage2_result,
            "behavioral": stage3_result,
            "verification": stage4_result,
            "confidence": stage5_result,
            "correlation": stage6_result,
            "baseline_snapshot": self._snapshot_response(baseline_response),
            "payload_snapshot": self._snapshot_response(payload_response),
        }

        if stage5_result.get("level") in ("confirmed", "high", "medium"):
            finding["severity"] = self._determine_severity(stage5_result, stage2_result)
            finding["cvss"] = self.cvss_calculator.calculate(
                finding["severity"], element, stage2_result
            )
            finding["vuln_type"] = self._determine_vuln_type(stage2_result, stage3_result)
            self.analysis_results.append(finding)
            self._update_payload_history(payload, finding)
            logger.info(
                f"Analysis {analysis_id}: Confidence={stage5_result.get('level')}, "
                f"Severity={finding.get('severity')}, Type={finding.get('vuln_type')}"
            )
        else:
            logger.info(
                f"Analysis {analysis_id}: Low/Informational - not elevated to finding"
            )

        return finding

    async def _stage1_differential_analysis(
        self,
        baseline_response: Dict[str, Any],
        payload_response: Dict[str, Any],
        payload: str,
        element: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        logger.debug("Stage 1: Differential analysis")
        metrics = self.differential.compare(baseline_response, payload_response)
        deviations = []
        if metrics.get("status_code_changed"):
            deviations.append("status_code")
        if metrics.get("response_time_deviation") and abs(
            metrics["response_time_deviation"]
        ) > 20:
            deviations.append("response_time")
        if metrics.get("content_length_delta") and abs(metrics["content_length_delta"]) > 50:
            deviations.append("content_length")
        if metrics.get("text_diff_ratio") and metrics["text_diff_ratio"] > 0.1:
            deviations.append("text_diff")
        if len(deviations) == 0:
            return None
        return {
            "deviations": deviations,
            "metrics": metrics,
            "significant": True,
            "deviation_count": len(deviations),
        }

    async def _stage2_pattern_matching(
        self,
        payload_response: Dict[str, Any],
        payload: str,
        element: Dict[str, Any],
    ) -> Dict[str, Any]:
        logger.debug("Stage 2: Pattern matching")
        body = payload_response.get("body", "")
        headers = payload_response.get("headers", {})
        header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        combined_text = body + "\n" + header_text

        sql_matches = self.pattern_matcher.match_sql_errors(combined_text)
        cmd_matches = self.pattern_matcher.match_command_output(combined_text)
        xss_matches = self.pattern_matcher.match_xss_reflection(combined_text, payload)
        ssti_matches = self.pattern_matcher.match_ssti(combined_text)
        xxe_matches = self.pattern_matcher.match_xxe(combined_text)
        ssrf_matches = self.pattern_matcher.match_ssrf(combined_text)
        error_stack_matches = self.pattern_matcher.match_error_stacks(combined_text)
        oob_matches = self.pattern_matcher.match_oob_indicators(combined_text)
        lfi_matches = self.pattern_matcher.match_lfi(combined_text)
        generic_matches = self.pattern_matcher.match_generic_indicators(combined_text)

        all_matches = {
            "sql_errors": sql_matches,
            "command_output": cmd_matches,
            "xss_reflection": xss_matches,
            "ssti": ssti_matches,
            "xxe": xxe_matches,
            "ssrf": ssrf_matches,
            "error_stacks": error_stack_matches,
            "oob_indicators": oob_matches,
            "lfi": lfi_matches,
            "generic": generic_matches,
        }

        definite = []
        probable = []
        for category, matches in all_matches.items():
            for match in matches:
                entry = {
                    "category": category,
                    "pattern": match.get("pattern_name", "unknown"),
                    "matched_text": match.get("matched_text", "")[:200],
                    "confidence": match.get("confidence", "low"),
                }
                if match.get("confidence") == "definite":
                    definite.append(entry)
                else:
                    probable.append(entry)

        return {
            "definite": definite,
            "probable": probable,
            "total_matches": len(definite) + len(probable),
            "definite_count": len(definite),
            "probable_count": len(probable),
            "has_definite": len(definite) > 0,
            "has_any_match": len(definite) + len(probable) > 0,
        }

    async def _stage3_behavioral_analysis(
        self,
        baseline_response: Dict[str, Any],
        payload_response: Dict[str, Any],
        payload: str,
        element: Dict[str, Any],
    ) -> Dict[str, Any]:
        logger.debug("Stage 3: Behavioral analysis")
        time_result = self.behavioral.time_based_check(
            baseline_response, payload_response
        )
        bool_result = self.behavioral.boolean_based_check(
            baseline_response, payload_response
        )
        content_result = self.behavioral.content_based_check(
            baseline_response, payload_response, payload
        )
        return {
            "time_based": time_result,
            "boolean_based": bool_result,
            "content_based": content_result,
            "any_indicator": (
                time_result.get("detected", False)
                or bool_result.get("detected", False)
                or content_result.get("detected", False)
            ),
        }

    async def _stage4_verification(
        self,
        original_payload: str,
        element: Dict[str, Any],
        pattern_result: Dict[str, Any],
        behavioral_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        logger.debug("Stage 4: Verification")
        verification_needed = pattern_result.get("has_any_match", False) or behavioral_result.get(
            "any_indicator", False
        )
        if not verification_needed:
            return {"verified": False, "reason": "no_indicators_to_verify"}

        verification_payloads = self.verifier.generate_verification_payloads(
            original_payload, pattern_result
        )
        if not verification_payloads:
            return {"verified": False, "reason": "no_verification_payloads_generated"}

        results = await self.verifier.verify_batch(verification_payloads, element, concurrency=5)
        
        confirmed_count = 0
        triggered_payload = None
        for i, result in enumerate(results):
            if result.get("confirmed"):
                confirmed_count += 1
                if not triggered_payload:
                    triggered_payload = verification_payloads[i]

        if confirmed_count > 0:
            return {
                "verified": True,
                "method": "re_payload",
                "triggered_payload": triggered_payload,
                "confirmed_count": confirmed_count,
                "total_attempts": len(results),
                "all_results": results,
            }

        return {
            "verified": False,
            "confirmed_count": 0,
            "total_attempts": len(results),
            "all_results": results,
        }

    async def _stage5_confidence_scoring(
        self,
        differential_result: Optional[Dict[str, Any]],
        pattern_result: Dict[str, Any],
        behavioral_result: Dict[str, Any],
        verification_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        logger.debug("Stage 5: Confidence scoring")
        return self.confidence_scorer.calculate(
            differential_result=differential_result,
            pattern_result=pattern_result,
            behavioral_result=behavioral_result,
            verification_result=verification_result,
        )

    async def _stage6_evidence_correlation(
        self,
        differential_result: Optional[Dict[str, Any]],
        pattern_result: Dict[str, Any],
        behavioral_result: Dict[str, Any],
        verification_result: Dict[str, Any],
        confidence_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        logger.debug("Stage 6: Evidence correlation")
        evidence_items = []
        if differential_result:
            evidence_items.append(
                {
                    "source": "differential",
                    "type": "metric_deviation",
                    "details": differential_result.get("deviations", []),
                    "weight": 0.3,
                }
            )
        for match in pattern_result.get("definite", []):
            evidence_items.append(
                {
                    "source": "pattern",
                    "type": "definite_match",
                    "category": match["category"],
                    "pattern": match["pattern"],
                    "weight": 0.9,
                }
            )
        for match in pattern_result.get("probable", []):
            evidence_items.append(
                {
                    "source": "pattern",
                    "type": "probable_match",
                    "category": match["category"],
                    "pattern": match["pattern"],
                    "weight": 0.6,
                }
            )
        for btype in ["time_based", "boolean_based", "content_based"]:
            bdata = behavioral_result.get(btype, {})
            if bdata.get("detected"):
                evidence_items.append(
                    {
                        "source": "behavioral",
                        "type": btype,
                        "details": bdata,
                        "weight": 0.7,
                    }
                )
        if verification_result.get("verified"):
            evidence_items.append(
                {
                    "source": "verification",
                    "type": "verified",
                    "method": verification_result.get("method"),
                    "weight": 0.95,
                }
            )

        deduplicated = self._deduplicate_evidence(evidence_items)
        correlated = self._correlate_evidence(deduplicated)

        return {
            "raw_evidence_count": len(evidence_items),
            "deduplicated_count": len(deduplicated),
            "evidence": deduplicated,
            "correlation": correlated,
            "cross_tool_consistency": self._check_cross_tool_consistency(
                differential_result, pattern_result, behavioral_result
            ),
        }

    def _deduplicate_evidence(self, evidence_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = {}
        for item in evidence_items:
            key = f"{item['source']}:{item['type']}:{item.get('category', '')}:{item.get('pattern', '')}"
            if key not in seen:
                seen[key] = item
            else:
                if item.get("weight", 0) > seen[key].get("weight", 0):
                    seen[key] = item
        return list(seen.values())

    def _correlate_evidence(self, evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
        categories = {}
        for item in evidence:
            cat = item.get("category", item.get("type", "unknown"))
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(item)
        correlated = {}
        for cat, items in categories.items():
            total_weight = sum(i.get("weight", 0) for i in items)
            source_count = len(set(i["source"] for i in items))
            correlated[cat] = {
                "count": len(items),
                "total_weight": round(total_weight, 3),
                "sources": list(set(i["source"] for i in items)),
                "source_diversity": source_count,
                "correlated_confidence": min(1.0, total_weight * (1 + 0.2 * (source_count - 1))),
            }
        return correlated

    def _check_cross_tool_consistency(
        self,
        differential_result: Optional[Dict[str, Any]],
        pattern_result: Dict[str, Any],
        behavioral_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        sources_agree = 0
        sources_total = 0
        if differential_result and differential_result.get("significant"):
            sources_total += 1
            sources_agree += 1
        if pattern_result.get("has_any_match"):
            sources_total += 1
            sources_agree += 1
        if behavioral_result.get("any_indicator"):
            sources_total += 1
            sources_agree += 1
        consistency = sources_agree / max(sources_total, 1)
        return {
            "sources_agreeing": sources_agree,
            "sources_total": sources_total,
            "consistency_ratio": round(consistency, 3),
            "multi_source": sources_agree >= 2,
        }

    def _snapshot_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status_code": response.get("status_code"),
            "content_length": response.get("content_length", 0),
            "response_time": response.get("response_time", 0),
            "header_count": len(response.get("headers", {})),
        }

    def _determine_severity(
        self, confidence_result: Dict[str, Any], pattern_result: Dict[str, Any]
    ) -> str:
        level = confidence_result.get("level", "low")
        if level == "confirmed":
            if pattern_result.get("definite_count", 0) >= 2:
                return "critical"
            return "high"
        if level == "high":
            if pattern_result.get("has_definite"):
                return "high"
            return "medium"
        if level == "medium":
            return "medium"
        return "low"

    def _determine_vuln_type(
        self, pattern_result: Dict[str, Any], behavioral_result: Dict[str, Any]
    ) -> str:
        categories_found = set()
        for match in pattern_result.get("definite", []) + pattern_result.get("probable", []):
            categories_found.add(match["category"])
        if "sql_errors" in categories_found:
            return "sql_injection"
        if "xss_reflection" in categories_found:
            return "cross_site_scripting"
        if "command_output" in categories_found:
            return "command_injection"
        if "ssti" in categories_found:
            return "server_side_template_injection"
        if "xxe" in categories_found:
            return "xml_external_entity"
        if "ssrf" in categories_found:
            return "server_side_request_forgery"
        if "lfi" in categories_found:
            return "local_file_inclusion"
        if behavioral_result.get("time_based", {}).get("detected"):
            return "blind_injection"
        if behavioral_result.get("boolean_based", {}).get("detected"):
            return "boolean_based_injection"
        return "unknown_injection"

    def _update_payload_history(self, payload: str, finding: Dict[str, Any]) -> None:
        family = self._extract_payload_family(payload)
        if family not in self.payload_history:
            self.payload_history[family] = []
        self.payload_history[family].append(
            {
                "payload": payload,
                "finding_id": finding["id"],
                "confidence": finding.get("confidence", {}).get("level", "low"),
                "timestamp": finding["timestamp"],
            }
        )

    def _extract_payload_family(self, payload: str) -> str:
        sql_keywords = ["union", "select", "insert", "update", "delete", "drop", "or ", "and "]
        xss_keywords = ["<script", "onerror", "onload", "javascript:", "alert("]
        cmd_keywords = [";", "|", "&&", "$(", "`", "whoami", "id", "cat "]
        payload_lower = payload.lower()
        for kw in sql_keywords:
            if kw in payload_lower:
                return "sql"
        for kw in xss_keywords:
            if kw in payload_lower:
                return "xss"
        for kw in cmd_keywords:
            if kw in payload_lower:
                return "cmd"
        return "generic"

    def get_all_findings(self) -> List[Dict[str, Any]]:
        return self.analysis_results

    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        return [f for f in self.analysis_results if f.get("severity") == severity]

    def get_payload_family_stats(self) -> Dict[str, Any]:
        stats = {}
        for family, entries in self.payload_history.items():
            confidences = [e["confidence"] for e in entries]
            stats[family] = {
                "count": len(entries),
                "confirmed": confidences.count("confirmed"),
                "high": confidences.count("high"),
                "medium": confidences.count("medium"),
                "low": confidences.count("low"),
            }
        return stats

    def get_statistics(self) -> Dict[str, Any]:
        total = len(self.analysis_results)
        if total == 0:
            return {"total_findings": 0}
        severities = {}
        vuln_types = {}
        confidences = {}
        for f in self.analysis_results:
            sev = f.get("severity", "unknown")
            severities[sev] = severities.get(sev, 0) + 1
            vtype = f.get("vuln_type", "unknown")
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
            conf = f.get("confidence", {}).get("level", "unknown")
            confidences[conf] = confidences.get(conf, 0) + 1
        avg_cvss = 0.0
        cvss_scores = [f.get("cvss", {}).get("base_score", 0) for f in self.analysis_results]
        if cvss_scores:
            avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 2)
        return {
            "total_findings": total,
            "severities": severities,
            "vuln_types": vuln_types,
            "confidences": confidences,
            "average_cvss": avg_cvss,
            "payload_families": len(self.payload_history),
        }
