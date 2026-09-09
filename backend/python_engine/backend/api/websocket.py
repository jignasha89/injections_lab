import socketio
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')


@sio.event
async def connect(sid, environ):
    logger.info(f"Client connected: {sid}")


@sio.event
async def disconnect(sid):
    logger.info(f"Client disconnected: {sid}")


async def emit_scan_progress(scan_id: str, payload: dict):
    payload["scan_id"] = scan_id
    payload["timestamp"] = datetime.utcnow().isoformat()
    if payload.get("phase"):
        try:
            from backend import memory_store
            memory_store.upsert_scan(
                scan_id,
                current_phase=str(payload.get("phase")),
                phase_percentage=payload.get("percentage"),
            )
        except Exception:
            pass
    await sio.emit("scan_progress", payload)


async def emit_finding(scan_id: str, finding: dict):
    await sio.emit(
        "finding_discovered",
        {
            "scan_id": scan_id,
            "finding": finding,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


async def emit_tool_output(
    scan_id: str,
    tool_name: str,
    output_line: str,
    level: str = "info",
):
    await sio.emit(
        "tool_output",
        {
            "scan_id": scan_id,
            "tool_name": tool_name,
            "output_line": output_line,
            "level": level,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


async def emit_scan_completed(
    scan_id: str,
    total_findings: int,
    duration: float,
    severity_summary: dict,
):
    await sio.emit(
        "scan_completed",
        {
            "scan_id": scan_id,
            "total_findings": total_findings,
            "duration": duration,
            "severity_summary": severity_summary,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


async def emit_scan_error(
    scan_id: str,
    error_message: str,
    tool_name: str = "",
):
    await sio.emit(
        "scan_error",
        {
            "scan_id": scan_id,
            "error_message": error_message,
            "tool_name": tool_name,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


async def emit_crawl_update(scan_id: str, payload: dict):
    payload["scan_id"] = scan_id
    payload["timestamp"] = datetime.utcnow().isoformat()
    await sio.emit("crawl_update", payload)
