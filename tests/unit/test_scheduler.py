from __future__ import annotations

import asyncio
from collections.abc import Callable

from netmon.scheduler import Scheduler
from netmon.service import Monitor
from tests.conftest import FakeRunner, fixture_xml, make_settings


async def _nosleep(_: float) -> None:
    await asyncio.sleep(0)


async def test_runs_each_job_and_limits_concurrency(
    monitor_factory: Callable[..., Monitor],
) -> None:
    settings = make_settings(
        jobs=[
            {"name": "a", "targets": ["192.0.2.0/29"]},
            {"name": "b", "targets": ["192.0.2.8/29"]},
            {"name": "off", "targets": ["192.0.2.16/29"], "enabled": False},
        ]
    )
    active = peak = 0

    class SlowRunner(FakeRunner):
        async def run(self, argv: list[str], timeout: float) -> str:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return await super().run(argv, timeout)

    runner = SlowRunner(*[fixture_xml("scan_baseline.xml")] * 4)
    sched = Scheduler(monitor_factory(runner, settings), settings.jobs, 1, sleep=_nosleep)
    await sched.run(max_runs=2)
    assert len(runner.calls) == 4  # 2 enabled jobs x 2 runs; disabled job never ran
    assert peak == 1


async def test_job_exception_does_not_kill_scheduler(
    monitor_factory: Callable[..., Monitor],
) -> None:
    settings = make_settings()
    monitor = monitor_factory(FakeRunner())
    calls = 0

    async def explode(job: object, **_: object) -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("bug")

    monitor.run_job = explode  # type: ignore[method-assign,assignment]
    await Scheduler(monitor, settings.jobs, 1, sleep=_nosleep).run(max_runs=3)
    assert calls == 3


async def test_stop_cancels_promptly(monitor_factory: Callable[..., Monitor]) -> None:
    settings = make_settings()
    sched = Scheduler(monitor_factory(FakeRunner()), settings.jobs, 1)  # real sleep (jitter)
    task = asyncio.create_task(sched.run())
    await asyncio.sleep(0.01)
    sched.stop()
    await asyncio.wait_for(task, 1)
