import asyncio
import logging
import signal
import os
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

from backend.api.websocket import emit_tool_output

logger = logging.getLogger(__name__)


class BaseAdapter(ABC):
    """Abstract base class for all tool adapters."""

    def __init__(self):
        self._processes: Dict[str, asyncio.subprocess.Process] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._results: Dict[str, list] = {}
        self._progress: Dict[str, float] = {}
        self._running: Dict[str, bool] = {}

    async def initialize(self) -> None:
        """Initialize the adapter, verify tool availability."""
        pass

    @abstractmethod
    async def start_scan(self, target: str, config: dict) -> str:
        """Start a scan against the target with given config. Returns session_id."""
        ...

    @abstractmethod
    async def get_results(self, session_id: str) -> list:
        """Return accumulated findings for the given session."""
        ...

    async def get_progress(self, session_id: str) -> float:
        """Return progress percentage (0-100) for the given session."""
        return self._progress.get(session_id, 0.0)

    async def stop_scan(self, session_id: str) -> bool:
        """Stop a running scan. Returns True if successfully stopped."""
        if session_id not in self._running or not self._running[session_id]:
            return False

        self._running[session_id] = False

        if session_id in self._tasks and not self._tasks[session_id].done():
            self._tasks[session_id].cancel()
            try:
                await self._tasks[session_id]
            except asyncio.CancelledError:
                pass

        if session_id in self._processes:
            proc = self._processes[session_id]
            try:
                if proc.returncode is None:
                    if os.name == "nt":
                        proc.kill()
                    else:
                        proc.send_signal(signal.SIGTERM)
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                proc.kill()
            except ProcessLookupError:
                pass
            finally:
                self._processes.pop(session_id, None)

        await emit_tool_output(
            session_id, self.__class__.__name__, "Scan stopped by user"
        )
        return True

    def is_running(self, session_id: str) -> bool:
        """Check if a scan is currently running for the given session."""
        return self._running.get(session_id, False)

    async def cleanup(self) -> None:
        """Clean up all running processes and resources."""
        session_ids = list(self._running.keys())
        for session_id in session_ids:
            if self._running[session_id]:
                await self.stop_scan(session_id)

        self._processes.clear()
        self._tasks.clear()
        self._results.clear()
        self._progress.clear()
        self._running.clear()

    async def _spawn_process(
        self,
        session_id: str,
        cmd: list[str],
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> asyncio.subprocess.Process:
        """Spawn an async subprocess and track it for the session."""
        merged_env = dict(os.environ)
        if env:
            merged_env.update(env)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=merged_env,
        )
        self._processes[session_id] = process
        return process

    async def _stream_output(
        self,
        session_id: str,
        process: asyncio.subprocess.Process,
        tool_name: str,
        parse_callback=None,
    ) -> None:
        """Stream stdout and stderr from a process, emitting events in real time."""
        async def _read_stream(stream, label):
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip("\r\n")
                if text:
                    await emit_tool_output(session_id, tool_name, text)
                    if parse_callback:
                        try:
                            parse_callback(text, session_id)
                        except Exception as e:
                            logger.debug(f"Parse callback error: {e}")

        stdout_task = asyncio.create_task(_read_stream(process.stdout, "stdout"))
        stderr_task = asyncio.create_task(_read_stream(process.stderr, "stderr"))
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
