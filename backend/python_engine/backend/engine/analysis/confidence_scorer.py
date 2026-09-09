import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ConfidenceScorer:
    def __init__(self):
        self.weights = {
            "differential": 0.2,
            "pattern_definite": 0.35,
            "pattern_probable": 0.15,
            "behavioral": 0.2,
            "verification": 0.4,
        }
        self.level_thresholds = {
            "confirmed": 0.85,
            "high": 0.65,
            "medium": 0.45,
            "low": 0.25,
            "informational": 0.0,
        }

    def calculate(
        self,
        differential_result: Optional[Dict[str, Any]],
        pattern_result: Dict[str, Any],
        behavioral_result: Dict[str, Any],
        verification_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        scores = {}
        reasons = []

        diff_score = self._score_differential(differential_result)
        scores["differential"] = diff_score
        if diff_score > 0:
            reasons.append(f"Response deviation detected (score={diff_score:.2f})")

        pattern_score = self._score_patterns(pattern_result)
        scores["pattern"] = pattern_score
        if pattern_result.get("has_definite"):
            reasons.append(
                f"Definite pattern matches found ({pattern_result.get('definite_count', 0)} matches)"
            )
        elif pattern_result.get("has_any_match"):
            reasons.append(
                f"Probable pattern matches found ({pattern_result.get('probable_count', 0)} matches)"
            )

        behavioral_score = self._score_behavioral(behavioral_result)
        scores["behavioral"] = behavioral_score
        if behavioral_score > 0:
            indicators = []
            if behavioral_result.get("time_based", {}).get("detected"):
                indicators.append("time-based")
            if behavioral_result.get("boolean_based", {}).get("detected"):
                indicators.append("boolean-based")
            if behavioral_result.get("content_based", {}).get("detected"):
                indicators.append("content-based")
            reasons.append(f"Behavioral indicators: {', '.join(indicators)}")

        verification_score = self._score_verification(verification_result)
        scores["verification"] = verification_score
        if verification_result.get("verified"):
            reasons.append("Payload verification confirmed indicators")

        composite_score = self._compute_composite_score(
            diff_score, pattern_score, behavioral_score, verification_score
        )
        scores["composite"] = composite_score

        level = self._determine_level(
            composite_score, verification_result, pattern_result, differential_result
        )

        consistency_bonus = self._compute_consistency_bonus(
            differential_result, pattern_result, behavioral_result, verification_result
        )
        adjusted_score = min(1.0, composite_score + consistency_bonus)
        scores["adjusted"] = adjusted_score

        if adjusted_score >= self.level_thresholds["confirmed"] and level != "confirmed":
            level = "confirmed"
            reasons.append("Consistency bonus elevated to confirmed")
        elif adjusted_score >= self.level_thresholds["high"] and level in ("medium", "low"):
            level = "high"
            reasons.append("Consistency bonus elevated to high")

        return {
            "level": level,
            "score": round(adjusted_score, 4),
            "raw_composite": round(composite_score, 4),
            "component_scores": scores,
            "consistency_bonus": round(consistency_bonus, 4),
            "reasons": reasons,
            "explanation": self._build_explanation(level, reasons),
        }

    def _score_differential(self, differential_result: Optional[Dict[str, Any]]) -> float:
        if not differential_result:
            return 0.0
        if not differential_result.get("significant"):
            return 0.0

        deviation_count = differential_result.get("deviation_count", 0)
        metrics = differential_result.get("metrics", {})

        score = 0.0
        if deviation_count >= 4:
            score += 0.4
        elif deviation_count >= 3:
            score += 0.3
        elif deviation_count >= 2:
            score += 0.2

        if metrics.get("status_code_changed"):
            score += 0.15

        text_diff = metrics.get("text_diff_ratio", 0)
        if text_diff > 0.5:
            score += 0.25
        elif text_diff > 0.3:
            score += 0.15
        elif text_diff > 0.1:
            score += 0.1

        rt_dev = abs(metrics.get("response_time_deviation", 0))
        if rt_dev > 100:
            score += 0.15
        elif rt_dev > 50:
            score += 0.1
        elif rt_dev > 20:
            score += 0.05

        cl_delta = abs(metrics.get("content_length_delta", 0))
        if cl_delta > 500:
            score += 0.1
        elif cl_delta > 200:
            score += 0.05

        return min(score, 1.0)

    def _score_patterns(self, pattern_result: Dict[str, Any]) -> float:
        definite_count = pattern_result.get("definite_count", 0)
        probable_count = pattern_result.get("probable_count", 0)

        if definite_count == 0 and probable_count == 0:
            return 0.0

        score = 0.0
        if definite_count >= 3:
            score += 0.8
        elif definite_count >= 2:
            score += 0.65
        elif definite_count >= 1:
            score += 0.5

        if probable_count >= 5:
            score += 0.2
        elif probable_count >= 3:
            score += 0.15
        elif probable_count >= 1:
            score += 0.1

        return min(score, 1.0)

    def _score_behavioral(self, behavioral_result: Dict[str, Any]) -> float:
        if not behavioral_result.get("any_indicator"):
            return 0.0

        score = 0.0
        time_result = behavioral_result.get("time_based", {})
        bool_result = behavioral_result.get("boolean_based", {})
        content_result = behavioral_result.get("content_based", {})

        if time_result.get("detected"):
            score += time_result.get("confidence", 0) * 0.35
        if bool_result.get("detected"):
            score += bool_result.get("confidence", 0) * 0.35
        if content_result.get("detected"):
            score += content_result.get("confidence", 0) * 0.3

        return min(score, 1.0)

    def _score_verification(self, verification_result: Dict[str, Any]) -> float:
        if verification_result.get("verified"):
            return 1.0
        if verification_result.get("confirmed_count", 0) > 0:
            total = verification_result.get("total_attempts", 1)
            confirmed = verification_result.get("confirmed_count", 0)
            return 0.5 + (confirmed / max(total, 1)) * 0.4
        return 0.0

    def _compute_composite_score(
        self,
        diff_score: float,
        pattern_score: float,
        behavioral_score: float,
        verification_score: float,
    ) -> float:
        composite = (
            diff_score * self.weights["differential"]
            + pattern_score * self.weights["pattern_definite"]
            + behavioral_score * self.weights["behavioral"]
            + verification_score * self.weights["verification"]
        )
        return min(composite, 1.0)

    def _determine_level(
        self,
        composite_score: float,
        verification_result: Dict[str, Any],
        pattern_result: Dict[str, Any],
        differential_result: Optional[Dict[str, Any]],
    ) -> str:
        is_verified = verification_result.get("verified", False)
        has_definite = pattern_result.get("has_definite", False)
        has_any_pattern = pattern_result.get("has_any_match", False)
        has_differential = differential_result is not None and differential_result.get(
            "significant", False
        )

        if is_verified and has_definite and composite_score >= self.level_thresholds["confirmed"]:
            return "confirmed"
        if is_verified and has_definite:
            return "high"
        if has_definite and has_differential and composite_score >= self.level_thresholds["medium"]:
            return "high"
        if has_definite:
            return "high"
        if is_verified and has_any_pattern:
            return "high"
        if has_any_pattern and has_differential:
            return "medium"
        if has_any_pattern:
            return "medium"
        if has_differential and composite_score >= self.level_thresholds["medium"]:
            return "medium"
        if has_differential:
            return "low"
        return "informational"

    def _compute_consistency_bonus(
        self,
        differential_result: Optional[Dict[str, Any]],
        pattern_result: Dict[str, Any],
        behavioral_result: Dict[str, Any],
        verification_result: Dict[str, Any],
    ) -> float:
        sources = 0
        if differential_result and differential_result.get("significant"):
            sources += 1
        if pattern_result.get("has_any_match"):
            sources += 1
        if behavioral_result.get("any_indicator"):
            sources += 1
        if verification_result.get("verified"):
            sources += 1

        if sources >= 4:
            return 0.15
        if sources >= 3:
            return 0.1
        if sources >= 2:
            return 0.05
        return 0.0

    def _build_explanation(self, level: str, reasons: List[str]) -> str:
        level_descriptions = {
            "confirmed": "Confirmed vulnerability with verification and definite pattern matches",
            "high": "High confidence vulnerability with strong indicators",
            "medium": "Medium confidence with moderate indicators",
            "low": "Low confidence with minor indicators",
            "informational": "Informational finding with minimal indicators",
        }
        base = level_descriptions.get(level, "Unknown confidence level")
        if reasons:
            return f"{base}. Evidence: {'; '.join(reasons)}"
        return base

    def calculate_severity_adjustment(
        self, base_severity: str, confidence_level: str, finding_count: int
    ) -> str:
        severity_order = ["critical", "high", "medium", "low", "informational"]
        confidence_adjustments = {
            "confirmed": 0,
            "high": 0,
            "medium": -1,
            "low": -2,
            "informational": -2,
        }
        base_idx = severity_order.index(base_severity) if base_severity in severity_order else 3
        adjustment = confidence_adjustments.get(confidence_level, 0)
        if finding_count >= 5:
            adjustment += 1
        elif finding_count >= 3:
            adjustment += 0
        new_idx = max(0, min(len(severity_order) - 1, base_idx - adjustment))
        return severity_order[new_idx]

    def compute_overall_risk_score(self, findings: list) -> Dict[str, Any]:
        if not findings:
            return {"score": 0, "level": "none", "finding_count": 0}

        severity_scores = {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "informational": 0.5,
        }

        total_score = 0.0
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            total_score += severity_scores.get(sev, 0)

        avg_score = total_score / len(findings)
        max_severity = "informational"
        for s in ["critical", "high", "medium", "low", "informational"]:
            if s in severity_counts:
                max_severity = s
                break

        if avg_score >= 8.0:
            risk_level = "critical"
        elif avg_score >= 6.0:
            risk_level = "high"
        elif avg_score >= 4.0:
            risk_level = "medium"
        elif avg_score >= 2.0:
            risk_level = "low"
        else:
            risk_level = "informational"

        return {
            "score": round(avg_score, 2),
            "level": risk_level,
            "max_severity": max_severity,
            "finding_count": len(findings),
            "severity_distribution": severity_counts,
        }
