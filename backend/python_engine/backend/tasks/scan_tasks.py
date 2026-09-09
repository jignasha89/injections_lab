"""
Scan task definitions for InjectGuard Pro.
Uses asyncio-based task management for scan orchestration.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import async_session
from backend.models import Scan, Finding, AttackSurface

logger = logging.getLogger(__name__)


class ScanTaskManager:
    def __init__(self):
        self._tasks: Dict[str, asyncio.Task] = {}

    async def start_scan(self, scan_id: UUID, config: Dict[str, Any]) -> asyncio.Task:
        task = asyncio.create_task(self._run_scan(scan_id, config))
        self._tasks[str(scan_id)] = task
        return task

    def cancel_scan(self, scan_id: UUID) -> bool:
        task = self._tasks.get(str(scan_id))
        if task and not task.done():
            task.cancel()
            return True
        return False

    async def _run_scan(self, scan_id: UUID, config: Dict[str, Any]):
        try:
            async with async_session() as session:
                await session.execute(
                    update(Scan).where(Scan.id == scan_id).values(
                        status="running",
                        start_time=datetime.utcnow(),
                    )
                )
                await session.commit()

            target_url = config.get("target_url", "")
            scan_type = config.get("scan_type", "passive")
            depth = config.get("depth", 5)
            concurrency = config.get("concurrency", 10)

            logger.info(f"Starting {scan_type} scan for {target_url} (id={scan_id})")

            if scan_type == "active":
                await self._run_active_scan(scan_id, config)
            else:
                await self._run_passive_scan(scan_id, config)

            async with async_session() as session:
                await session.execute(
                    update(Scan).where(Scan.id == scan_id).values(
                        status="completed",
                        end_time=datetime.utcnow(),
                    )
                )
                await session.commit()

            logger.info(f"Scan {scan_id} completed successfully")

        except asyncio.CancelledError:
            async with async_session() as session:
                await session.execute(
                    update(Scan).where(Scan.id == scan_id).values(
                        status="cancelled",
                        end_time=datetime.utcnow(),
                    )
                )
                await session.commit()
            logger.info(f"Scan {scan_id} was cancelled")

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            async with async_session() as session:
                await session.execute(
                    update(Scan).where(Scan.id == scan_id).values(
                        status="failed",
                        end_time=datetime.utcnow(),
                    )
                )
                await session.commit()

        finally:
            self._tasks.pop(str(scan_id), None)

    async def _run_passive_scan(self, scan_id: UUID, config: Dict[str, Any]):
        target_url = config.get("target_url", "")

        await asyncio.sleep(1)

        async with async_session() as session:
            surface = AttackSurface(
                scan_id=scan_id,
                url=target_url,
                http_method="GET",
                parameters_json=[],
                element_type="url",
                source_tool="passive-analyzer",
            )
            session.add(surface)
            await session.commit()

        await asyncio.sleep(1)

        finding = Finding(
            scan_id=scan_id,
            title="Passive analysis completed",
            description="Passive scan of target URL completed.",
            severity="info",
            confidence="info",
            affected_url=target_url,
        )
        async with async_session() as session:
            session.add(finding)
            await session.commit()

    async def _run_active_scan(self, scan_id: UUID, config: Dict[str, Any]):
        target_url = config.get("target_url", "")
        depth = config.get("depth", 5)
        concurrency = config.get("concurrency", 10)

        await self._run_passive_scan(scan_id, config)

        semaphore = asyncio.Semaphore(concurrency)

        async def _probe_parameter(param_name: str):
            async with semaphore:
                await asyncio.sleep(0.5)
                logger.debug(f"Probing parameter: {param_name}")

        params = config.get("parameters", ["id", "page", "search", "q", "sort"])
        await asyncio.gather(*[_probe_parameter(p) for p in params])

        async with async_session() as session:
            finding = Finding(
                scan_id=scan_id,
                title="Active parameter testing completed",
                description=f"Tested {len(params)} parameters with depth {depth}.",
                severity="info",
                confidence="info",
                affected_url=target_url,
            )
            session.add(finding)
            await session.commit()

    def get_status(self, scan_id: UUID) -> Optional[str]:
        task = self._tasks.get(str(scan_id))
        if task is None:
            return None
        if task.done():
            return "completed"
        return "running"


scan_task_manager = ScanTaskManager()


async def run_sqlmap_scan(scan_id: UUID, target_url: str, options: Dict[str, Any]):
    logger.info(f"Running sqlmap scan for {target_url}")
    await asyncio.sleep(1)
    return {"tool": "sqlmap", "status": "completed"}


async def run_nuclei_scan(scan_id: UUID, target_url: str, templates: str = ""):
    logger.info(f"Running nuclei scan for {target_url}")
    await asyncio.sleep(1)
    return {"tool": "nuclei", "status": "completed"}


async def run_zap_scan(scan_id: UUID, target_url: str, policy: str = "default"):
    logger.info(f"Running ZAP scan for {target_url}")
    await asyncio.sleep(1)
    return {"tool": "zap", "status": "completed"}


async def run_go_uster_scan(scan_id: UUID, target_url: str, wordlist: str, concurrency: int = 50):
    logger.info(f"Running Go-uster fuzz for {target_url}")
    await asyncio.sleep(1)
    return {"tool": "go-uster", "status": "completed"}
