"""In-memory fallback storage.

Keeps the product usable when PostgreSQL is unreachable (blocked port,
missing service, etc.): scans still run end-to-end and results are served
from memory. Data lives only for the lifetime of the backend process.
"""
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_lock = threading.Lock()

# scan_id -> record dict shaped like the API's ScanDetail payload
scans: Dict[str, Dict[str, Any]] = {}
# scan_id -> list of finding dicts
findings: Dict[str, List[Dict[str, Any]]] = {}
# scan_id -> list of endpoint dicts (attack surface)
surfaces: Dict[str, List[Dict[str, Any]]] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_scan(scan_id: str, **fields) -> Dict[str, Any]:
    with _lock:
        record = scans.setdefault(scan_id, {
            "id": scan_id,
            "target_url": "",
            "status": "pending",
            "config": {},
            "created_at": _now(),
            "start_time": None,
            "end_time": None,
            "current_phase": "",
            "error_message": "",
            "findings_count": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        })
        record.update(fields)
        return record


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        return scans.get(scan_id)


def list_scans() -> List[Dict[str, Any]]:
    with _lock:
        return list(scans.values())


def delete_scan(scan_id: str) -> None:
    with _lock:
        scans.pop(scan_id, None)
        findings.pop(scan_id, None)
        surfaces.pop(scan_id, None)


def clear_all() -> int:
    """Remove every scan/finding/surface record. Returns count removed."""
    with _lock:
        removed = len(scans)
        scans.clear()
        findings.clear()
        surfaces.clear()
        return removed


def set_scan_status(scan_id: str, status: str, extra: Optional[Dict[str, Any]] = None) -> None:
    fields: Dict[str, Any] = {"status": status}
    if status in ("completed", "failed", "stopped", "cancelled"):
        fields["end_time"] = _now()
    if extra:
        fields.update(extra)
    upsert_scan(scan_id, **fields)


def add_findings(scan_id: str, new_findings: List[Dict[str, Any]]) -> None:
    with _lock:
        bucket = findings.setdefault(scan_id, [])
        bucket.extend(new_findings)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in bucket:
            sev = str(f.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1
        record = scans.get(scan_id)
        if record is not None:
            record["findings_count"] = len(bucket)
            record["severity_counts"] = counts


def get_findings(scan_id: str) -> List[Dict[str, Any]]:
    with _lock:
        return list(findings.get(scan_id, []))


def set_surface(scan_id: str, endpoints: List[Dict[str, Any]]) -> None:
    with _lock:
        surfaces[scan_id] = endpoints


def get_surface(scan_id: str) -> List[Dict[str, Any]]:
    with _lock:
        return list(surfaces.get(scan_id, []))
