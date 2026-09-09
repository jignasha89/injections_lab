import json
import logging
import os
from pathlib import Path
from typing import Optional

from backend.config import settings

logger = logging.getLogger(__name__)

FAMILY_FILES = {
    "sqli": "sqli.json",
    "nosql": "nosql.json",
    "xss": "xss.json",
    "cmdi": "cmdi.json",
    "ssti": "ssti.json",
    "path_traversal": "path_traversal.json",
    "xxe": "xxe.json",
    "ssrf": "ssrf.json",
    "open_redirect": "open_redirect.json",
    "crlf": "crlf.json",
    "header_injection": "header_injection.json",
    "email_injection": "email_injection.json",
    "code_injection": "code_injection.json",
    "formula_injection": "formula_injection.json",
    "xpath": "xpath.json",
    "htmli": "htmli.json",
    "texti": "texti.json",
    "ldapi": "ldapi.json",
    "object_injection": "object_injection.json",
    "xml_injection": "xml_injection.json",
    "protocol_injection": "protocol_injection.json",
    "parameter_pollution": "parameter_pollution.json",
    "log_injection": "log_injection.json",
    "prompt_injection": "prompt_injection.json",
    "modern_injection": "modern_injection.json",
    "css_injection": "css_injection.json",
    "ssi_injection": "ssi_injection.json",
    "null_byte": "null_byte.json",
    "unicode_injection": "unicode_injection.json",
    "regex_injection": "regex_injection.json",
    "pdf_injection": "pdf_injection.json"
}

ALL_FAMILIES = list(FAMILY_FILES.keys())


class PayloadDB:
    def __init__(self, payloads_dir: Optional[str] = None):
        self.payloads_dir = payloads_dir or os.path.join(
            settings.BASE_DIR, "backend", "engine", "attack", "families"
        )
        self._cache: dict[str, list[dict]] = {}
        self._waf_bypasses: list[dict] = []
        self._loaded = False

    def _ensure_loaded(self):
        if not self._loaded:
            self.load_all()

    def load_all(self):
        self._cache = {}
        for family, filename in FAMILY_FILES.items():
            filepath = os.path.join(self.payloads_dir, filename)
            self._cache[family] = self._load_json(filepath)
        self._waf_bypasses = self._load_waf_bypasses()
        self._loaded = True
        total = sum(len(p) for p in self._cache.values())
        logger.info(f"Loaded {total} payloads across {len(self._cache)} families")

    def _load_json(self, filepath: str) -> list[dict]:
        try:
            if not os.path.exists(filepath):
                logger.warning(f"Payload file not found: {filepath}")
                return []
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                logger.warning(f"Payload file {filepath} is not a JSON array")
                return []
            return data
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error in {filepath}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error loading {filepath}: {e}")
            return []

    def _load_waf_bypasses(self) -> list[dict]:
        waf_path = os.path.join(self.payloads_dir, "waf_bypasses.json")
        return self._load_json(waf_path)

    def get_payloads_by_family(self, family: str) -> list[dict]:
        self._ensure_loaded()
        return list(self._cache.get(family, []))

    def get_payloads_by_subtype(self, family: str, subtype: str) -> list[dict]:
        self._ensure_loaded()
        return [
            p for p in self._cache.get(family, [])
            if p.get("subtype") == subtype
        ]

    def get_payloads_by_context(
        self, context: str, family: Optional[str] = None
    ) -> list[dict]:
        self._ensure_loaded()
        results = []
        families = [family] if family else ALL_FAMILIES
        for fam in families:
            for p in self._cache.get(fam, []):
                if p.get("context") == context:
                    results.append(p)
        return results

    def get_payloads_by_technology(self, technology: str) -> list[dict]:
        self._ensure_loaded()
        tech_lower = technology.lower()
        results = []
        for family, payloads in self._cache.items():
            for p in payloads:
                platform = p.get("platform_specific", {})
                if tech_lower in platform:
                    results.append(p)
                elif any(
                    tech_lower in k.lower() for k in platform.keys()
                ):
                    results.append(p)
        return results

    def search(
        self,
        family: Optional[str] = None,
        subtype: Optional[str] = None,
        context: Optional[str] = None,
        technology: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        self._ensure_loaded()
        results = []

        candidates = self._cache.get(family, []) if family else []
        if not candidates:
            candidates = []
            for fam_payloads in self._cache.values():
                candidates.extend(fam_payloads)

        for p in candidates:
            if family and p.get("family") != family:
                continue
            if subtype and p.get("subtype") != subtype:
                continue
            if context and p.get("context") != context:
                continue
            if technology:
                tech_lower = technology.lower()
                platform = p.get("platform_specific", {})
                if not any(tech_lower in k.lower() for k in platform.keys()):
                    continue
            results.append(p)
            if len(results) >= limit:
                break

        return results

    def get_random_payloads(
        self, family: str, count: int = 5
    ) -> list[dict]:
        import random
        self._ensure_loaded()
        payloads = self._cache.get(family, [])
        if not payloads:
            return []
        return random.sample(payloads, min(count, len(payloads)))

    def get_waf_bypasses(self) -> list[dict]:
        self._ensure_loaded()
        return list(self._waf_bypasses)

    def get_waf_bypasses_for_family(self, family: str) -> list[dict]:
        self._ensure_loaded()
        return [
            b for b in self._waf_bypasses
            if b.get("family") == family or not b.get("family")
        ]

    def get_all_families(self) -> list[str]:
        return list(FAMILY_FILES.keys())

    def get_family_stats(self) -> dict:
        self._ensure_loaded()
        stats = {}
        for family, payloads in self._cache.items():
            subtypes = {}
            for p in payloads:
                st = p.get("subtype", "unknown")
                subtypes[st] = subtypes.get(st, 0) + 1
            stats[family] = {
                "total": len(payloads),
                "subtypes": subtypes,
            }
        return stats

    def reload(self):
        self._loaded = False
        self.load_all()

    def add_payload(self, payload: dict) -> bool:
        family = payload.get("family")
        if family not in FAMILY_FILES:
            logger.error(f"Unknown family: {family}")
            return False
        self._ensure_loaded()
        self._cache.setdefault(family, []).append(payload)
        return True

    def count_total(self) -> int:
        self._ensure_loaded()
        return sum(len(p) for p in self._cache.values())
