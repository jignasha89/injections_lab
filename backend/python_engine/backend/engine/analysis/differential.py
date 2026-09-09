import re
import math
import logging
import statistics
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

DYNAMIC_PATTERNS = [
    (r"csrf[_-]?token['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_=]+", "csrf_token"),
    (r"session[_-]?id['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_=]+", "session_id"),
    (r"nonce['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_=]+", "nonce"),
    (r"timestamp['\"]?\s*[:=]\s*['\"]?\d{10,13}", "timestamp"),
    (r"date['\"]?\s*[:=]\s*['\"]?\d{4}-\d{2}-\d{2}", "date"),
    (r"time['\"]?\s*[:=]\s*['\"]?\d{2}:\d{2}:\d{2}", "time"),
    (r"request[_-]?id['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_=]+", "request_id"),
    (r"trace[_-]?id['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_=]+", "trace_id"),
    (r"span[_-]?id['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_=]+", "span_id"),
    (r"transaction[_-]?id['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_=]+", "transaction_id"),
    (r"uuid['\"]?\s*[:=]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "uuid"),
    (r"[0-9a-f]{32,}", "hex_hash"),
    (r"_[0-9a-f]{8,}", "hex_suffix"),
    (r"\b\d{10,13}\b", "unix_timestamp"),
    (r"JSESSIONID=[A-Za-z0-9]+", "jsessionid"),
    (r"PHPSESSID=[A-Za-z0-9]+", "phpsessid"),
    (r"ASP\.NET_SessionId=[A-Za-z0-9]+", "aspnet_session"),
    (r"__cfduid=[A-Za-z0-9]+", "cfduid"),
    (r"X-Request-Id:\s*[A-Za-z0-9\-_=]+", "request_header_id"),
    (r"X-Trace-Id:\s*[A-Za-z0-9\-_=]+", "trace_header_id"),
    (r"ETag:\s*\"[^\"]+\"", "etag"),
    (r"Last-Modified:\s*.*", "last_modified"),
    (r"Cache-Control:\s*.*", "cache_control"),
    (r"Set-Cookie:\s*.*", "set_cookie"),
    (r"Authorization:\s*.*", "authorization"),
]


class DifferentialAnalyzer:
    def __init__(self):
        self.dynamic_patterns = [(re.compile(p, re.IGNORECASE), name) for p, name in DYNAMIC_PATTERNS]

    def compare(
        self,
        baseline: Dict[str, Any],
        payload_response: Dict[str, Any],
        tolerance: float = 0.2,
    ) -> Dict[str, Any]:
        baseline_body = self._extract_body(baseline)
        payload_body = self._extract_body(payload_response)
        clean_baseline = self._strip_dynamic_content(baseline_body)
        clean_payload = self._strip_dynamic_content(payload_body)

        status_code = self._compare_status_codes(baseline, payload_response)
        response_time = self._compare_response_times(baseline, payload_response)
        content_length = self._compare_content_lengths(baseline_body, payload_body)
        text_diff = self._calculate_text_diff_ratio(clean_baseline, clean_payload)

        baseline_tokens = self._tokenize(clean_baseline)
        payload_tokens = self._tokenize(clean_payload)
        token_diff = self._calculate_token_diff(baseline_tokens, payload_tokens)

        baseline_sentences = self._split_sentences(clean_baseline)
        payload_sentences = self._split_sentences(clean_payload)
        sentence_diff = self._calculate_sentence_diff(baseline_sentences, payload_sentences)

        significant_change_ratio = text_diff.get("change_ratio", 0)
        structural_similarity = text_diff.get("structural_similarity", 1.0)

        return {
            "status_code_changed": status_code["changed"],
            "status_code_baseline": status_code["baseline"],
            "status_code_payload": status_code["payload"],
            "response_time_deviation": response_time["deviation_percent"],
            "response_time_baseline": response_time["baseline"],
            "response_time_payload": response_time["payload"],
            "content_length_delta": content_length["delta"],
            "content_length_baseline": content_length["baseline"],
            "content_length_payload": content_length["payload"],
            "text_diff_ratio": text_diff["change_ratio"],
            "text_diff_added_lines": text_diff["added"],
            "text_diff_removed_lines": text_diff["removed"],
            "text_diff_common_lines": text_diff["common"],
            "structural_similarity": structural_similarity,
            "token_diff_ratio": token_diff["ratio"],
            "token_diff_added": token_diff["added"],
            "token_diff_removed": token_diff["removed"],
            "sentence_diff_ratio": sentence_diff["ratio"],
            "dynamic_content_stripped": True,
            "tolerance": tolerance,
            "significant": self._is_significant(
                status_code, response_time, content_length, text_diff, tolerance
            ),
        }

    def _extract_body(self, response: Dict[str, Any]) -> str:
        body = response.get("body", "")
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8", errors="replace")
            except Exception:
                body = str(body)
        return body

    # regex passes over huge bodies (binary/large files) take minutes —
    # differential comparison beyond this size is meaningless anyway
    MAX_ANALYZE_BODY = 200_000

    def _strip_dynamic_content(self, text: str) -> str:
        if not text:
            return ""
        if len(text) > self.MAX_ANALYZE_BODY:
            text = text[:self.MAX_ANALYZE_BODY]
        cleaned = text
        for pattern, name in self.dynamic_patterns:
            cleaned = pattern.sub(f"[DYNAMIC:{name}]", cleaned)
        cleaned = re.sub(r"\b\d{13,}\b", "[TIMESTAMP]", cleaned)
        cleaned = re.sub(r"\b\d{10}\b", "[EPOCH]", cleaned)
        cleaned = re.sub(r"\b[0-9a-f]{32,}\b", "[HASH]", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(
            r"['\"]?X-[\w-]+['\"]?\s*:\s*['\"][^'\"]+['\"]",
            "[HEADER]",
            cleaned,
        )
        return cleaned

    def _compare_status_codes(
        self, baseline: Dict[str, Any], payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        b_code = baseline.get("status_code", 200)
        p_code = payload.get("status_code", 200)
        return {
            "baseline": b_code,
            "payload": p_code,
            "changed": b_code != p_code,
            "delta": p_code - b_code,
            "error_to_success": b_code >= 400 and p_code < 400,
            "success_to_error": b_code < 400 and p_code >= 400,
        }

    def _compare_response_times(
        self, baseline: Dict[str, Any], payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        b_time = baseline.get("response_time", 0) or 0
        p_time = payload.get("response_time", 0) or 0
        if b_time == 0:
            deviation = 100.0 if p_time > 0 else 0.0
        else:
            deviation = ((p_time - b_time) / b_time) * 100
        return {
            "baseline": b_time,
            "payload": p_time,
            "deviation_percent": round(deviation, 2),
            "absolute_delta": round(abs(p_time - b_time), 4),
        }

    def _compare_content_lengths(self, baseline_body: str, payload_body: str) -> Dict[str, Any]:
        b_len = len(baseline_body)
        p_len = len(payload_body)
        delta = p_len - b_len
        if b_len == 0:
            percent_change = 100.0 if p_len > 0 else 0.0
        else:
            percent_change = (delta / b_len) * 100
        return {
            "baseline": b_len,
            "payload": p_len,
            "delta": delta,
            "percent_change": round(percent_change, 2),
        }

    def _calculate_text_diff_ratio(self, text1: str, text2: str) -> Dict[str, Any]:
        if not text1 and not text2:
            return {
                "change_ratio": 0.0,
                "added": 0,
                "removed": 0,
                "common": 0,
                "structural_similarity": 1.0,
            }
        lines1 = text1.splitlines()
        lines2 = text2.splitlines()
        lcs_len = self._lcs_length(lines1, lines2)
        total_lines = max(len(lines1), len(lines2), 1)
        added = len(lines2) - lcs_len
        removed = len(lines1) - lcs_len
        common = lcs_len
        change_ratio = (added + removed) / total_lines
        structural_similarity = lcs_len / total_lines if total_lines > 0 else 1.0
        return {
            "change_ratio": round(min(change_ratio, 1.0), 4),
            "added": max(added, 0),
            "removed": max(removed, 0),
            "common": common,
            "structural_similarity": round(structural_similarity, 4),
        }

    def _lcs_length(self, seq1: List[str], seq2: List[str]) -> int:
        m, n = len(seq1), len(seq2)
        if m == 0 or n == 0:
            return 0
        prev = [0] * (n + 1)
        curr = [0] * (n + 1)
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if seq1[i - 1] == seq2[j - 1]:
                    curr[j] = prev[j - 1] + 1
                else:
                    curr[j] = max(prev[j], curr[j - 1])
            prev, curr = curr, [0] * (n + 1)
        return prev[n]

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"\b\w+\b", text.lower())

    def _calculate_token_diff(self, tokens1: List[str], tokens2: List[str]) -> Dict[str, Any]:
        set1 = set(tokens1)
        set2 = set(tokens2)
        added = set2 - set1
        removed = set1 - set2
        common = set1 & set2
        total = set1 | set2
        ratio = 1.0 - (len(common) / max(len(total), 1))
        return {
            "ratio": round(ratio, 4),
            "added": len(added),
            "removed": len(removed),
            "common": len(common),
        }

    def _split_sentences(self, text: str) -> List[str]:
        sentences = re.split(r"[.!?]+", text)
        return [s.strip() for s in sentences if s.strip()]

    def _calculate_sentence_diff(
        self, sents1: List[str], sents2: List[str]
    ) -> Dict[str, Any]:
        set1 = set(sents1)
        set2 = set(sents2)
        common = set1 & set2
        total = set1 | set2
        ratio = 1.0 - (len(common) / max(len(total), 1))
        return {
            "ratio": round(ratio, 4),
            "added": len(set2 - set1),
            "removed": len(set1 - set2),
            "common": len(common),
        }

    def _is_significant(
        self,
        status_code: Dict[str, Any],
        response_time: Dict[str, Any],
        content_length: Dict[str, Any],
        text_diff: Dict[str, Any],
        tolerance: float,
    ) -> bool:
        indicators = 0
        if status_code.get("changed"):
            indicators += 1
        if abs(response_time.get("deviation_percent", 0)) > 20:
            indicators += 1
        if abs(content_length.get("delta", 0)) > 50:
            indicators += 1
        if text_diff.get("change_ratio", 0) > 0.1:
            indicators += 1
        return indicators >= 2

    def get_baseline_statistics(
        self, baselines: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not baselines:
            return {}
        status_codes = [b.get("status_code", 200) for b in baselines]
        response_times = [b.get("response_time", 0) or 0 for b in baselines]
        content_lengths = []
        for b in baselines:
            body = self._extract_body(b)
            content_lengths.append(len(body))
        result = {}
        if status_codes:
            result["status_code_mode"] = max(set(status_codes), key=status_codes.count)
            result["status_code_values"] = list(set(status_codes))
        if response_times:
            result["response_time_mean"] = round(statistics.mean(response_times), 4)
            result["response_time_median"] = round(statistics.median(response_times), 4)
            if len(response_times) > 1:
                result["response_time_stdev"] = round(statistics.stdev(response_times), 4)
            else:
                result["response_time_stdev"] = 0.0
        if content_lengths:
            result["content_length_mean"] = round(statistics.mean(content_lengths), 2)
            result["content_length_median"] = round(statistics.median(content_lengths), 2)
            if len(content_lengths) > 1:
                result["content_length_stdev"] = round(statistics.stdev(content_lengths), 2)
            else:
                result["content_length_stdev"] = 0.0
        result["baseline_count"] = len(baselines)
        return result

    def compute_consistency_score(
        self, baselines: List[Dict[str, Any]]
    ) -> float:
        if len(baselines) < 2:
            return 1.0
        codes = [b.get("status_code", 200) for b in baselines]
        code_consistency = 1.0 - (len(set(codes)) - 1) / max(len(codes) - 1, 1)
        times = [b.get("response_time", 0) or 0 for b in baselines]
        if len(times) > 1 and statistics.mean(times) > 0:
            cv = statistics.stdev(times) / max(statistics.mean(times), 0.001)
            time_consistency = max(0.0, 1.0 - cv)
        else:
            time_consistency = 1.0
        lengths = [len(self._extract_body(b)) for b in baselines]
        if len(lengths) > 1 and statistics.mean(lengths) > 0:
            cv = statistics.stdev(lengths) / max(statistics.mean(lengths), 1)
            length_consistency = max(0.0, 1.0 - cv)
        else:
            length_consistency = 1.0
        return round((code_consistency + time_consistency + length_consistency) / 3, 4)
