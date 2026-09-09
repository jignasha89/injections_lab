import asyncio
import importlib
import logging
import os
import traceback
from typing import Optional

from backend.api.websocket import emit_tool_output, emit_finding
from backend.config import settings
from backend.engine.tools.base_adapter import BaseAdapter

logger = logging.getLogger(__name__)

FAMILIES_DIR = os.path.join(
    settings.BASE_DIR, "backend", "engine", "attack", "families"
)


class CustomAdapter(BaseAdapter):
    """Generic adapter for running custom Python attack family modules."""

    def __init__(self):
        super().__init__()
        self._loaded_modules: dict[str, object] = {}
        self._module_scan_tasks: dict[str, list[asyncio.Task]] = {}

    async def initialize(self) -> None:
        """Discover and load available attack family modules."""
        if not os.path.isdir(FAMILIES_DIR):
            logger.warning(f"Families directory not found: {FAMILIES_DIR}")
            return

        for filename in os.listdir(FAMILIES_DIR):
            if filename.startswith("_") or not filename.endswith(".py"):
                continue
            module_name = filename[:-3]
            try:
                module = self._load_family_module(module_name)
                if module and hasattr(module, "scan"):
                    self._loaded_modules[module_name] = module
                    logger.info(f"Loaded family module: {module_name}")
            except Exception as e:
                logger.warning(f"Failed to load family module {module_name}: {e}")

        await emit_tool_output(
            "system", "custom_adapter",
            f"Loaded {len(self._loaded_modules)} attack family modules: "
            f"{', '.join(sorted(self._loaded_modules.keys()))}",
        )

    def _load_family_module(self, module_name: str):
        """Dynamically load a family module."""
        module_path = os.path.join(FAMILIES_DIR, f"{module_name}.py")
        if not os.path.isfile(module_path):
            return None

        spec = importlib.util.spec_from_file_location(
            f"backend.engine.attack.families.{module_name}",
            module_path,
        )
        if not spec or not spec.loader:
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    async def start_scan(self, target: str, config: dict) -> str:
        """Run custom family modules against target elements."""
        session_id = config.get("scan_id", f"custom_{id(config)}")
        self._running[session_id] = True
        self._results[session_id] = []
        self._progress[session_id] = 0.0
        self._module_scan_tasks[session_id] = []

        task = asyncio.create_task(
            self._run_custom_scan(session_id, target, config)
        )
        self._tasks[session_id] = task
        return session_id

    async def _run_custom_scan(
        self, session_id: str, target: str, config: dict
    ) -> None:
        """Execute all configured family modules."""
        try:
            families = config.get("families", list(self._loaded_modules.keys()))
            elements = config.get("elements", [])
            payloads = config.get("payloads", {})
            concurrency = config.get("concurrency", settings.CONCURRENCY_DEFAULT)
            rate_limit = config.get("rate_limit", settings.RATE_LIMIT_DEFAULT)

            if not elements:
                elements = [
                    {
                        "url": target,
                        "http_method": "GET",
                        "parameter_name": "",
                        "element_type": "url",
                        "scan_id": session_id,
                    }
                ]

            available_families = [
                f for f in families if f in self._loaded_modules
            ]
            if not available_families:
                await emit_tool_output(
                    session_id, "custom_adapter",
                    "No matching family modules found for configured families",
                )
                return

            total_tasks = len(available_families) * len(elements)
            completed = 0

            await emit_tool_output(
                session_id, "custom_adapter",
                f"Starting custom scan: {len(available_families)} families, "
                f"{len(elements)} elements, {total_tasks} total tasks",
            )

            sem = asyncio.Semaphore(concurrency)
            rate_sem = asyncio.Semaphore(rate_limit)

            async def _run_module_on_element(
                family_name: str, element: dict, element_idx: int
            ):
                nonlocal completed
                async with sem:
                    async with rate_sem:
                        if not self._running.get(session_id, False):
                            return

                        module = self._loaded_modules[family_name]
                        element_payloads = payloads.get(family_name, [])

                        try:
                            await emit_tool_output(
                                session_id, "custom_adapter",
                                f"Running {family_name} on {element.get('url', '')}",
                            )

                            result = await module.scan(element, element_payloads)

                            if result and isinstance(result, list):
                                for finding in result:
                                    if isinstance(finding, dict):
                                        self._results[session_id].append(finding)
                                        await emit_finding(session_id, finding)
                                        await emit_tool_output(
                                            session_id, "custom_adapter",
                                            f"[{finding.get('severity', 'info').upper()}] "
                                            f"{finding.get('title', 'Unknown finding')}",
                                        )

                        except asyncio.CancelledError:
                            raise
                        except Exception as e:
                            logger.error(
                                f"Error running {family_name} on "
                                f"{element.get('url', '')}: {e}"
                            )
                            tb = traceback.format_exc()
                            await emit_tool_output(
                                session_id, "custom_adapter",
                                f"Error in {family_name}: {str(e)}\n{tb}",
                            )
                        finally:
                            completed += 1
                            progress = (completed / total_tasks) * 100
                            self._progress[session_id] = progress
                            await emit_tool_output(
                                session_id, "custom_adapter",
                                f"Progress: {progress:.1f}% ({completed}/{total_tasks})",
                            )

            all_coros = []
            for family_name in available_families:
                for idx, element in enumerate(elements):
                    coro = _run_module_on_element(
                        family_name, element, idx
                    )
                    all_coros.append(asyncio.create_task(coro))
                    self._module_scan_tasks[session_id].append(
                        all_coros[-1]
                    )

            await asyncio.gather(*all_coros, return_exceptions=True)

            self._progress[session_id] = 100.0
            await emit_tool_output(
                session_id, "custom_adapter",
                f"Custom scan complete. Found {len(self._results[session_id])} findings.",
            )
        except asyncio.CancelledError:
            await emit_tool_output(
                session_id, "custom_adapter", "Scan cancelled"
            )
        except Exception as e:
            logger.error(f"Custom scan error: {e}")
            await emit_tool_output(
                session_id, "custom_adapter", f"Scan error: {str(e)}"
            )
        finally:
            self._running[session_id] = False
            self._module_scan_tasks.pop(session_id, None)

    async def stop_scan(self, session_id: str) -> bool:
        """Stop a running custom scan and cancel module tasks."""
        tasks = self._module_scan_tasks.get(session_id, [])
        for t in tasks:
            if not t.done():
                t.cancel()
        return await super().stop_scan(session_id)

    async def get_results(self, session_id: str) -> list:
        """Return accumulated findings."""
        return self._results.get(session_id, [])

    def get_available_modules(self) -> dict[str, dict]:
        """Return info about all loaded family modules."""
        modules_info = {}
        for name, module in self._loaded_modules.items():
            info = {
                "name": name,
                "has_scan": hasattr(module, "scan"),
                "has_class": any(
                    hasattr(module, attr)
                    for attr in dir(module)
                    if isinstance(getattr(module, attr, None), type)
                ),
            }
            if hasattr(module, "SQLiScanner"):
                info["class_name"] = "SQLiScanner"
            elif hasattr(module, "XSSScanner"):
                info["class_name"] = "XSSScanner"

            for attr_name in dir(module):
                attr = getattr(module, attr_name, None)
                if isinstance(attr, type) and hasattr(attr, "scan"):
                    info["class_name"] = attr_name
                    break

            modules_info[name] = info
        return modules_info

    async def scan_single_module(
        self,
        session_id: str,
        module_name: str,
        element: dict,
        payloads: list[dict],
    ) -> list[dict]:
        """Run a single family module on a single element."""
        if module_name not in self._loaded_modules:
            await emit_tool_output(
                session_id, "custom_adapter",
                f"Module '{module_name}' not loaded",
            )
            return []

        module = self._loaded_modules[module_name]
        try:
            await emit_tool_output(
                session_id, "custom_adapter",
                f"Running single module: {module_name}",
            )
            result = await module.scan(element, payloads)
            if result and isinstance(result, list):
                for finding in result:
                    if isinstance(finding, dict):
                        self._results.setdefault(session_id, []).append(finding)
                        await emit_finding(session_id, finding)
                return result
            return []
        except Exception as e:
            logger.error(f"Error running module {module_name}: {e}")
            await emit_tool_output(
                session_id, "custom_adapter",
                f"Module error: {str(e)}",
            )
            return []
