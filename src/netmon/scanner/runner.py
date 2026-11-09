"""Execute Nmap safely as an asyncio subprocess."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import signal
from typing import Protocol

log = logging.getLogger(__name__)

# Only these variables reach the nmap process; nothing secret leaks via the environment.
_ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "TZ", "NMAPDIR")
_MAX_STDERR = 4096


class NmapError(RuntimeError):
    """Base class for execution failures."""

    transient = True


class NmapNotFound(NmapError):
    transient = False


class NmapTimeout(NmapError):
    pass


class NmapFailed(NmapError):
    def __init__(self, returncode: int, stderr: str) -> None:
        super().__init__(f"nmap exited with {returncode}: {stderr.strip()[:_MAX_STDERR]}")
        self.returncode = returncode
        self.stderr = stderr


class Runner(Protocol):
    async def run(self, argv: list[str], timeout: float) -> str: ...


class NmapRunner:
    """Runs nmap without a shell, with a hard timeout and a scrubbed environment."""

    async def run(self, argv: list[str], timeout: float) -> str:
        binary = shutil.which(argv[0])
        if binary is None:
            raise NmapNotFound(f"nmap binary {argv[0]!r} not found on PATH")
        env = {k: v for k, v in os.environ.items() if k in _ENV_ALLOWLIST}
        log.debug("exec %s", argv)
        proc = await asyncio.create_subprocess_exec(
            binary,
            *argv[1:],
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            start_new_session=True,  # own process group so we can kill nmap's children too
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            _kill(proc)
            await proc.wait()
            raise NmapTimeout(f"nmap exceeded {timeout:.0f}s timeout") from None
        except asyncio.CancelledError:
            _kill(proc)
            with contextlib.suppress(Exception):
                await asyncio.shield(proc.wait())
            raise
        if proc.returncode != 0:
            raise NmapFailed(proc.returncode or -1, stderr.decode(errors="replace"))
        if stderr:
            log.debug("nmap stderr: %s", stderr.decode(errors="replace")[:_MAX_STDERR])
        return stdout.decode(errors="replace")


def _kill(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)
