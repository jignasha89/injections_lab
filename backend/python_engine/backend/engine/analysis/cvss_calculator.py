import logging
import math
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class CVSSCalculator:
    CVSS_VERSION = "3.1"

    SEVERITY_RANGES = [
        (0.0, 0.0, "None", "#000000"),
        (0.1, 3.9, "Low", "#FFC0CB"),
        (4.0, 6.9, "Medium", "#FFD700"),
        (7.0, 8.9, "High", "#FF8C00"),
        (9.0, 10.0, "Critical", "#FF0000"),
    ]

    VULN_TYPE_VECTORS = {
        "sql_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "blind_sql_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
        "cross_site_scripting": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
        "command_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "server_side_template_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "xml_external_entity": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
        "server_side_request_forgery": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
        "local_file_inclusion": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
        "remote_file_inclusion": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "directory_traversal": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
        "os_command_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "ldap_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
        "xpath_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
        "nosql_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
        "header_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"},
        "email_header_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "L", "A": "L"},
        "log_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "L", "A": "N"},
        "deserialization": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "prototype_pollution": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
        "expression_language_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "code_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "blind_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
        "boolean_based_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
        "time_based_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "L"},
        "unknown_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "L"},
    }

    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_WEIGHTS_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_WEIGHTS_S = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    IMPACT_WEIGHTS = {"N": 0.00, "L": 0.22, "H": 0.56}
    SCOPE_WEIGHTS = {"U": 0.0, "C": 1.08}

    def __init__(self):
        pass

    def calculate(
        self,
        severity: str,
        element: Dict[str, Any],
        pattern_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        vuln_type = self._infer_vuln_type(pattern_result)
        base_metrics = self._get_default_metrics(vuln_type)
        adjusted = self._adjust_for_context(base_metrics, element, severity)
        score = self._compute_score(adjusted)
        vector = self._build_vector_string(adjusted)
        severity_label = self._score_to_severity(score)

        return {
            "version": self.CVSS_VERSION,
            "vector_string": vector,
            "base_score": round(score, 1),
            "severity": severity_label,
            "metrics": adjusted,
            "vuln_type": vuln_type,
        }

    def calculate_from_metrics(self, metrics: Dict[str, str]) -> Dict[str, Any]:
        required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        for m in required:
            if m not in metrics:
                raise ValueError(f"Missing required CVSS metric: {m}")
        score = self._compute_score(metrics)
        vector = self._build_vector_string(metrics)
        severity_label = self._score_to_severity(score)
        return {
            "version": self.CVSS_VERSION,
            "vector_string": vector,
            "base_score": round(score, 1),
            "severity": severity_label,
            "metrics": metrics,
        }

    def _infer_vuln_type(self, pattern_result: Optional[Dict[str, Any]]) -> str:
        if not pattern_result:
            return "unknown_injection"
        categories = set()
        for match in pattern_result.get("definite", []) + pattern_result.get("probable", []):
            categories.add(match.get("category", ""))
        if "sql_errors" in categories:
            return "sql_injection"
        if "xss_reflection" in categories:
            return "cross_site_scripting"
        if "command_output" in categories:
            return "command_injection"
        if "ssti" in categories:
            return "server_side_template_injection"
        if "xxe" in categories:
            return "xml_external_entity"
        if "ssrf" in categories:
            return "server_side_request_forgery"
        if "lfi" in categories:
            return "local_file_inclusion"
        return "unknown_injection"

    def _get_default_metrics(self, vuln_type: str) -> Dict[str, str]:
        defaults = self.VULN_TYPE_VECTORS.get(vuln_type, self.VULN_TYPE_VECTORS["unknown_injection"])
        return dict(defaults)

    def _adjust_for_context(
        self,
        metrics: Dict[str, str],
        element: Dict[str, Any],
        severity: str,
    ) -> Dict[str, Any]:
        adjusted = dict(metrics)
        position = element.get("position", "query")
        if position == "header":
            adjusted["AC"] = "H"
        if position == "cookie":
            adjusted["AC"] = "H"
        if position == "body":
            adjusted["AV"] = "N"
        if severity == "critical":
            adjusted["C"] = "H"
            adjusted["I"] = "H"
            adjusted["A"] = "H"
        elif severity == "high":
            adjusted["C"] = "H"
            adjusted["I"] = "H"
        elif severity == "medium":
            adjusted["C"] = "L"
            adjusted["I"] = "L"
        elif severity == "low":
            adjusted["C"] = "L"
            adjusted["I"] = "N"
            adjusted["A"] = "N"
        auth_required = element.get("auth_required", False)
        if auth_required:
            adjusted["PR"] = "L"
        return adjusted

    def _compute_score(self, metrics: Dict[str, str]) -> float:
        av = self.AV_WEIGHTS.get(metrics["AV"], 0.85)
        ac = self.AC_WEIGHTS.get(metrics["AC"], 0.77)
        scope = metrics["S"]
        if scope == "S":
            pr = self.PR_WEIGHTS_S.get(metrics["PR"], 0.85)
        else:
            pr = self.PR_WEIGHTS_U.get(metrics["PR"], 0.85)
        ui = self.UI_WEIGHTS.get(metrics["UI"], 0.85)
        exploitability = 8.22 * av * ac * pr * ui
        c_impact = self.IMPACT_WEIGHTS.get(metrics["C"], 0.0)
        i_impact = self.IMPACT_WEIGHTS.get(metrics["I"], 0.0)
        a_impact = self.IMPACT_WEIGHTS.get(metrics["A"], 0.0)
        impact_sub = 1 - ((1 - c_impact) * (1 - i_impact) * (1 - a_impact))
        if impact_sub <= 0:
            return 0.0
        if scope == "S":
            impact = 7.52 * (impact_sub - 0.029) - 3.25 * ((impact_sub - 0.02) ** 15)
        else:
            impact = 6.42 * impact_sub
        if impact <= 0:
            return 0.0
        if scope == "S":
            base = min(1.08 * (exploitability + impact), 10.0)
        else:
            base = min(exploitability + impact, 10.0)
        return self._roundup(base)

    def _roundup(self, x: float) -> float:
        return math.ceil(x * 10) / 10

    def _build_vector_string(self, metrics: Dict[str, str]) -> str:
        parts = [
            f"CVSS:{self.CVSS_VERSION}",
            f"AV:{metrics.get('AV', 'N')}",
            f"AC:{metrics.get('AC', 'L')}",
            f"PR:{metrics.get('PR', 'N')}",
            f"UI:{metrics.get('UI', 'N')}",
            f"S:{metrics.get('S', 'U')}",
            f"C:{metrics.get('C', 'N')}",
            f"I:{metrics.get('I', 'N')}",
            f"A:{metrics.get('A', 'N')}",
        ]
        return "/".join(parts)

    def _score_to_severity(self, score: float) -> str:
        if score == 0.0:
            return "None"
        for low, high, label, _ in self.SEVERITY_RANGES:
            if low <= score <= high:
                return label
        if score > 10.0:
            return "Critical"
        return "Low"

    def _score_to_color(self, score: float) -> str:
        if score == 0.0:
            return "#000000"
        for low, high, _, color in self.SEVERITY_RANGES:
            if low <= score <= high:
                return color
        return "#FF0000"

    def parse_vector_string(self, vector: str) -> Dict[str, str]:
        parts = vector.split("/")
        metrics = {}
        for part in parts[1:]:
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value
        return metrics

    def calculate_temporal(
        self,
        base_metrics: Dict[str, str],
        exploit_code_maturity: str = "X",
        remediation_level: str = "X",
        report_confidence: str = "X",
    ) -> Dict[str, Any]:
        temporal = dict(base_metrics)
        temporal["E"] = exploit_code_maturity
        temporal["RL"] = remediation_level
        temporal["RC"] = report_confidence
        base_score = self._compute_score(base_metrics)
        e_weights = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
        rl_weights = {"X": 1.0, "U": 1.0, "W": 0.96, "T": 0.91, "O": 0.86}
        rc_weights = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}
        temporal_score = base_score * e_weights.get(exploit_code_maturity, 1.0) * rl_weights.get(remediation_level, 1.0) * rc_weights.get(report_confidence, 1.0)
        temporal_score = min(temporal_score, 10.0)
        temporal_score = self._roundup(temporal_score)
        return {
            "version": self.CVSS_VERSION,
            "base_score": round(base_score, 1),
            "temporal_score": round(temporal_score, 1),
            "severity": self._score_to_severity(temporal_score),
            "metrics": temporal,
        }

    def calculate_environmental(
        self,
        base_metrics: Dict[str, str],
        confidentiality_req: str = "X",
        integrity_req: str = "X",
        availability_req: str = "X",
        modified_av: str = "X",
        modified_ac: str = "X",
        modified_pr: str = "X",
        modified_ui: str = "X",
        modified_s: str = "X",
        modified_c: str = "X",
        modified_i: str = "X",
        modified_a: str = "X",
    ) -> Dict[str, Any]:
        env_metrics = dict(base_metrics)
        env_metrics["CR"] = confidentiality_req
        env_metrics["IR"] = integrity_req
        env_metrics["AR"] = availability_req
        if modified_av != "X":
            env_metrics["MAV"] = modified_av
        if modified_ac != "X":
            env_metrics["MAC"] = modified_ac
        if modified_pr != "X":
            env_metrics["MPR"] = modified_pr
        if modified_ui != "X":
            env_metrics["MUI"] = modified_ui
        if modified_s != "X":
            env_metrics["MS"] = modified_s
        if modified_c != "X":
            env_metrics["MC"] = modified_c
        if modified_i != "X":
            env_metrics["MI"] = modified_i
        if modified_a != "X":
            env_metrics["MA"] = modified_a
        mod_metrics = {}
        mod_metrics["AV"] = env_metrics.get("MAV", env_metrics["AV"])
        mod_metrics["AC"] = env_metrics.get("MAC", env_metrics["AC"])
        mod_metrics["PR"] = env_metrics.get("MPR", env_metrics["PR"])
        mod_metrics["UI"] = env_metrics.get("MUI", env_metrics["UI"])
        mod_metrics["S"] = env_metrics.get("MS", env_metrics["S"])
        mod_metrics["C"] = env_metrics.get("MC", env_metrics["C"])
        mod_metrics["I"] = env_metrics.get("MI", env_metrics["I"])
        mod_metrics["A"] = env_metrics.get("MA", env_metrics["A"])
        env_score = self._compute_score(mod_metrics)
        return {
            "version": self.CVSS_VERSION,
            "environmental_score": round(env_score, 1),
            "severity": self._score_to_severity(env_score),
            "metrics": env_metrics,
            "modified_metrics": mod_metrics,
        }

    def compare_vectors(self, vector1: str, vector2: str) -> Dict[str, Any]:
        m1 = self.parse_vector_string(vector1)
        m2 = self.parse_vector_string(vector2)
        diffs = {}
        all_keys = set(list(m1.keys()) + list(m2.keys()))
        for key in all_keys:
            v1 = m1.get(key, "N/A")
            v2 = m2.get(key, "N/A")
            if v1 != v2:
                diffs[key] = {"vector1": v1, "vector2": v2}
        s1 = self.compute_score_from_parsed(m1)
        s2 = self.compute_score_from_parsed(m2)
        return {
            "differences": diffs,
            "score1": round(s1, 1),
            "score2": round(s2, 1),
            "severity1": self._score_to_severity(s1),
            "severity2": self._score_to_severity(s2),
        }

    def compute_score_from_parsed(self, metrics: Dict[str, str]) -> float:
        required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        clean = {}
        for m in required:
            clean[m] = metrics.get(m, "N")
        return self._compute_score(clean)

    def get_severity_info(self, score: float) -> Dict[str, Any]:
        for low, high, label, color in self.SEVERITY_RANGES:
            if low <= score <= high:
                return {"label": label, "color": color, "score": round(score, 1)}
        return {"label": "Unknown", "color": "#808080", "score": round(score, 1)}
