import time
import logging
import statistics
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class BehavioralAnalyzer:
    def __init__(self):
        self.time_threshold_percent = 20.0
        self.min_response_time = 0.1
        self.boolean_consistency_threshold = 0.6

    def time_based_check(
        self,
        baseline_response: Dict[str, Any],
        payload_response: Dict[str, Any],
        additional_baselines: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        baseline_time = baseline_response.get("response_time", 0) or 0
        payload_time = payload_response.get("response_time", 0) or 0

        if baseline_time == 0 and payload_time == 0:
            return {
                "detected": False,
                "method": "time",
                "reason": "no_timing_data",
                "baseline_time": 0,
                "payload_time": 0,
                "deviation_percent": 0,
            }

        if baseline_time == 0:
            deviation = 100.0 if payload_time > 0 else 0.0
        else:
            deviation = ((payload_time - baseline_time) / baseline_time) * 100

        significant_delay = deviation > self.time_threshold_percent
        significant_speedup = deviation < -self.time_threshold_percent

        consistent_baseline = True
        if additional_baselines and len(additional_baselines) >= 2:
            base_times = [b.get("response_time", 0) or 0 for b in additional_baselines]
            base_times.append(baseline_time)
            if len(base_times) > 2:
                cv = statistics.stdev(base_times) / max(statistics.mean(base_times), 0.001)
                consistent_baseline = cv < 0.3
            else:
                avg_time = statistics.mean(base_times)
                for t in base_times:
                    if abs(t - avg_time) / max(avg_time, 0.001) > 0.5:
                        consistent_baseline = False
                        break

        timing_anomaly = (significant_delay or significant_speedup) and consistent_baseline
        pattern = "consistent_delay" if significant_delay else "consistent_speedup"
        if timing_anomaly:
            pattern = self._classify_timing_pattern(
                baseline_time, payload_time, additional_baselines
            )

        return {
            "detected": timing_anomaly,
            "method": "time",
            "baseline_time": baseline_time,
            "payload_time": payload_time,
            "deviation_percent": round(deviation, 2),
            "absolute_delta": round(abs(payload_time - baseline_time), 4),
            "significant_delay": significant_delay,
            "significant_speedup": significant_speedup,
            "consistent_baseline": consistent_baseline,
            "pattern": pattern,
            "confidence": self._calculate_time_confidence(
                deviation, significant_delay, significant_speedup, consistent_baseline
            ),
        }

    def _classify_timing_pattern(
        self,
        baseline_time: float,
        payload_time: float,
        additional_baselines: Optional[List[Dict[str, Any]]],
    ) -> str:
        if payload_time > baseline_time * 3:
            return "large_delay"
        if payload_time > baseline_time * 2:
            return "double_delay"
        if payload_time > baseline_time * 1.5:
            return "moderate_delay"
        if payload_time > baseline_time:
            return "slight_delay"
        if payload_time < baseline_time * 0.5:
            return "significant_speedup"
        if payload_time < baseline_time * 0.7:
            return "moderate_speedup"
        return "slight_speedup"

    def _calculate_time_confidence(
        self,
        deviation: float,
        significant_delay: bool,
        significant_speedup: bool,
        consistent_baseline: bool,
    ) -> float:
        if not (significant_delay or significant_speedup):
            return 0.0
        if not consistent_baseline:
            return 0.1
        abs_dev = abs(deviation)
        if abs_dev > 500:
            return 0.95
        if abs_dev > 200:
            return 0.85
        if abs_dev > 100:
            return 0.75
        if abs_dev > 50:
            return 0.65
        if abs_dev > 30:
            return 0.55
        return 0.45

    def boolean_based_check(
        self,
        baseline_response: Dict[str, Any],
        payload_response: Dict[str, Any],
        true_false_pair: Optional[tuple] = None,
    ) -> Dict[str, Any]:
        baseline_body = self._extract_body_text(baseline_response)
        payload_body = self._extract_body_text(payload_response)
        baseline_status = baseline_response.get("status_code", 200)
        payload_status = payload_response.get("status_code", 200)
        baseline_length = len(baseline_body)
        payload_length = len(payload_body)

        status_differs = baseline_status != payload_status
        length_differs = abs(baseline_length - payload_length) > 50
        content_differs = self._content_differs_significantly(baseline_body, payload_body)

        false_body = None
        true_body = None
        if true_false_pair:
            true_resp, false_resp = true_false_pair
            true_body = self._extract_body_text(true_resp)
            false_body = self._extract_body_text(false_resp)

        true_false_different = False
        if true_body is not None and false_body is not None:
            true_false_different = self._content_differs_significantly(true_body, false_body)

        boolean_detected = (
            (status_differs or length_differs or content_differs)
            and not true_false_different
        )

        if true_false_pair:
            true_false_ratio = self._compute_boolean_ratio(
                baseline_body, payload_body, true_body, false_body
            )
        else:
            true_false_ratio = 0.0

        response_characteristics = {
            "baseline_hash": hash(baseline_body),
            "payload_hash": hash(payload_body),
            "baseline_status": baseline_status,
            "payload_status": payload_status,
            "baseline_length": baseline_length,
            "payload_length": payload_length,
            "length_delta": payload_length - baseline_length,
        }

        if true_false_pair:
            response_characteristics["true_hash"] = hash(true_body)
            response_characteristics["false_hash"] = hash(false_body)

        pattern = self._classify_boolean_pattern(
            status_differs, length_differs, content_differs, baseline_status, payload_status
        )

        return {
            "detected": boolean_detected,
            "method": "boolean",
            "status_differs": status_differs,
            "length_differs": length_differs,
            "content_differs": content_differs,
            "true_false_different": true_false_different,
            "true_false_ratio": round(true_false_ratio, 3),
            "pattern": pattern,
            "characteristics": response_characteristics,
            "confidence": self._calculate_boolean_confidence(
                status_differs, length_differs, content_differs, true_false_different, true_false_ratio
            ),
        }

    def _extract_body_text(self, response: Dict[str, Any]) -> str:
        body = response.get("body", "")
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8", errors="replace")
            except Exception:
                body = str(body)
        return body

    def _content_differs_significantly(self, text1: str, text2: str) -> bool:
        if text1 == text2:
            return False
        if not text1 or not text2:
            return True
        lines1 = set(text1.splitlines())
        lines2 = set(text2.splitlines())
        if not lines1 and not lines2:
            return text1 != text2
        common = lines1 & lines2
        total = lines1 | lines2
        similarity = len(common) / max(len(total), 1)
        return similarity < 0.8

    def _compute_boolean_ratio(
        self,
        baseline: str,
        payload: str,
        true_body: str,
        false_body: str,
    ) -> float:
        baseline_len = len(baseline)
        payload_len = len(payload)
        true_len = len(true_body)
        false_len = len(false_body)

        if baseline_len == 0 and payload_len == 0:
            return 0.0

        baseline_payload_similarity = 1.0 - abs(baseline_len - payload_len) / max(
            baseline_len + payload_len, 1
        )
        true_false_similarity = 1.0 - abs(true_len - false_len) / max(
            true_len + false_len, 1
        )

        if true_false_similarity > 0.9:
            return 0.0

        payload_closer_to_true = abs(payload_len - true_len) < abs(payload_len - false_len)
        baseline_closer_to_true = abs(baseline_len - true_len) < abs(baseline_len - false_len)

        if payload_closer_to_true != baseline_closer_to_true:
            return 0.8
        return 0.2

    def _classify_boolean_pattern(
        self,
        status_differs: bool,
        length_differs: bool,
        content_differs: bool,
        baseline_status: int,
        payload_status: int,
    ) -> str:
        if status_differs:
            if baseline_status < 400 and payload_status >= 400:
                return "error_on_true"
            if baseline_status >= 400 and payload_status < 400:
                return "success_on_true"
            return "status_change"
        if length_differs:
            return "length_based"
        if content_differs:
            return "content_based"
        return "no_difference"

    def _calculate_boolean_confidence(
        self,
        status_differs: bool,
        length_differs: bool,
        content_differs: bool,
        true_false_different: bool,
        true_false_ratio: float,
    ) -> float:
        if true_false_different:
            return 0.0
        confidence = 0.0
        if status_differs:
            confidence += 0.4
        if length_differs:
            confidence += 0.3
        if content_differs:
            confidence += 0.3
        confidence = min(confidence, 0.8)
        return round(confidence, 3)

    def content_based_check(
        self,
        baseline_response: Dict[str, Any],
        payload_response: Dict[str, Any],
        payload: str,
    ) -> Dict[str, Any]:
        baseline_body = self._extract_body_text(baseline_response)
        payload_body = self._extract_body_text(payload_response)
        payload_reflected = payload in payload_body if payload else False
        baseline_headers = baseline_response.get("headers", {})
        payload_headers = payload_response.get("headers", {})
        header_diffs = self._compare_headers(baseline_headers, payload_headers)
        baseline_content_type = baseline_headers.get("content-type", "")
        payload_content_type = payload_headers.get("content-type", "")
        content_type_changed = baseline_content_type != payload_content_type

        error_patterns_found = []
        error_keywords = [
            "error", "exception", "warning", "fatal", "critical",
            "debug", "trace", "stack", "failure", "denied",
        ]
        payload_lower = payload_body.lower()
        for keyword in error_keywords:
            if keyword in payload_lower and keyword not in baseline_body.lower():
                error_patterns_found.append(keyword)

        stack_trace_detected = False
        stack_patterns = [
            "traceback", "stack trace", "call stack",
            "at line", "file \"", ".java:", ".py:", ".php:",
        ]
        for pattern in stack_patterns:
            if pattern.lower() in payload_lower and pattern.lower() not in baseline_body.lower():
                stack_trace_detected = True
                break

        content_analysis = {
            "payload_reflected": payload_reflected,
            "payload_reflection_position": self._find_payload_position(payload_body, payload) if payload_reflected else -1,
            "content_type_changed": content_type_changed,
            "baseline_content_type": baseline_content_type,
            "payload_content_type": payload_content_type,
            "header_diffs": header_diffs,
            "header_diff_count": len(header_diffs),
            "error_patterns_found": error_patterns_found,
            "error_pattern_count": len(error_patterns_found),
            "stack_trace_detected": stack_trace_detected,
        }

        detected = (
            payload_reflected
            or content_type_changed
            or len(error_patterns_found) > 0
            or stack_trace_detected
            or len(header_diffs) > 3
        )

        confidence = 0.0
        if payload_reflected:
            confidence += 0.35
        if stack_trace_detected:
            confidence += 0.3
        if len(error_patterns_found) > 2:
            confidence += 0.25
        elif len(error_patterns_found) > 0:
            confidence += 0.15
        if content_type_changed:
            confidence += 0.15
        if len(header_diffs) > 3:
            confidence += 0.1
        confidence = min(confidence, 0.9)

        return {
            "detected": detected,
            "method": "content",
            "content_analysis": content_analysis,
            "confidence": round(confidence, 3),
            "indicators": {
                "payload_reflected": payload_reflected,
                "stack_trace": stack_trace_detected,
                "error_patterns": len(error_patterns_found) > 0,
                "content_type_change": content_type_changed,
            },
        }

    def _compare_headers(
        self, baseline_headers: Dict[str, str], payload_headers: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        diffs = []
        all_keys = set(list(baseline_headers.keys()) + list(payload_headers.keys()))
        for key in all_keys:
            b_val = baseline_headers.get(key, "")
            p_val = payload_headers.get(key, "")
            if b_val != p_val:
                diffs.append(
                    {
                        "header": key,
                        "baseline": b_val[:200],
                        "payload": p_val[:200],
                        "added": key not in baseline_headers,
                        "removed": key not in payload_headers,
                        "modified": key in baseline_headers and key in payload_headers,
                    }
                )
        return diffs

    def _find_payload_position(self, text: str, payload: str) -> int:
        if not payload:
            return -1
        return text.find(payload)

    def detect_blind_injection(
        self,
        baseline_response: Dict[str, Any],
        payload_response: Dict[str, Any],
        payload_type: str = "unknown",
    ) -> Dict[str, Any]:
        time_check = self.time_based_check(baseline_response, payload_response)
        bool_check = self.boolean_based_check(baseline_response, payload_response)
        content_check = self.content_based_check(
            baseline_response, payload_response, ""
        )

        indicators = []
        if time_check.get("detected"):
            indicators.append("time")
        if bool_check.get("detected"):
            indicators.append("boolean")
        if content_check.get("detected"):
            indicators.append("content")

        blind_detected = len(indicators) >= 1
        confidence = 0.0
        if time_check.get("detected"):
            confidence += time_check.get("confidence", 0)
        if bool_check.get("detected"):
            confidence += bool_check.get("confidence", 0)
        if content_check.get("detected"):
            confidence += content_check.get("confidence", 0)
        confidence = min(confidence, 0.9)

        injection_type = "blind"
        if time_check.get("detected") and time_check.get("pattern") in (
            "large_delay",
            "double_delay",
        ):
            injection_type = "time_based_blind"
        elif bool_check.get("detected"):
            injection_type = "boolean_based_blind"

        return {
            "detected": blind_detected,
            "injection_type": injection_type,
            "payload_type": payload_type,
            "indicators": indicators,
            "time_analysis": time_check,
            "boolean_analysis": bool_check,
            "content_analysis": content_check,
            "confidence": round(confidence, 3),
        }
