"""asyncio scheduler: one long-lived task per job, a global concurrency semaphore,
initial jitter to spread load, and graceful cancellation (nmap is killed on shutdown).

Concurrency model: everything is I/O bound (waiting on nmap subprocesses, HTTP, SQLite in
a worker thread), so a single event loop is sufficient. Nmap itself is the parallel engine;
multiprocessing would add complexity without throughput gains.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable

from netmon.config import Job
from netmon.service import Monitor, RunOutcome

log = logging.getLogger(__name__)
Sleep = Callable[[float], Awaitable[None]]


class Scheduler:
    def __init__(
        self,
        monitor: Monitor,
        jobs: list[Job],
        max_concurrent: int,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self.monitor = monitor
        self.jobs = [j for j in jobs if j.enabled]
        self._sem = asyncio.Semaphore(max_concurrent)
        self._sleep = sleep
        self._tasks: list[asyncio.Task[None]] = []
        self._stop = asyncio.Event()

    async def run_once(self, job: Job) -> RunOutcome:
        async with self._sem:
            return await self.monitor.run_job(job)

    async def _loop(self, job: Job, max_runs: int | None) -> None:
        # Random initial offset so N jobs don't all fire at start-up.
        await self._sleep(random.uniform(0, job.jitter))  # noqa: S311
        runs = 0
        while not self._stop.is_set():
            try:
                await self.run_once(job)
            except asyncio.CancelledError:
                raise
            except Exception:
                # A bug in one job must not kill the scheduler; it's logged and retried
                # on the next interval.
                log.exception("unhandled error in job %s", job.name, extra={"job": job.name})
            runs += 1
            if max_runs is not None and runs >= max_runs:
                return
            await self._sleep(job.interval + random.uniform(0, job.jitter))  # noqa: S311

    async def run(self, max_runs: int | None = None) -> None:
        """Run until :meth:`stop` is called (or each job ran ``max_runs`` times)."""
        if not self.jobs:
            log.warning("no enabled jobs; scheduler idle")
            return
        log.info("scheduler starting with jobs: %s", ", ".join(j.name for j in self.jobs))
        self._tasks = [
            asyncio.create_task(self._loop(j, max_runs), name=f"job:{j.name}") for j in self.jobs
        ]
        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            if not self._stop.is_set():
                raise  # cancelled from outside: propagate
            # stop() was called: graceful shutdown, not an error.
        finally:
            for t in self._tasks:
                t.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)

    def stop(self) -> None:
        self._stop.set()
        for t in self._tasks:
            t.cancel()
