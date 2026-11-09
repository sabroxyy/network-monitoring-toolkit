from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, time

from netmon.models import ChangeKind, ScanStatus
from netmon.scanner import NmapFailed, NmapNotFound, NmapTimeout
from netmon.service import Monitor
from netmon.storage.sqlite import SQLiteStorage
from tests.conftest import FakeRunner, RecordingNotifier, fixture_xml, make_settings

Factory = Callable[..., Monitor]


async def test_baseline_then_changes_alert(
    monitor_factory: Factory, notifier: RecordingNotifier, storage: SQLiteStorage
) -> None:
    runner = FakeRunner(fixture_xml("scan_baseline.xml"), fixture_xml("scan_changed.xml"))
    monitor = monitor_factory(runner)
    job = monitor.settings.job("lab")

    first = await monitor.run_job(job)
    assert first.status is ScanStatus.SUCCEEDED and first.changes == []
    assert notifier.sent == []

    second = await monitor.run_job(job)
    kinds = {c.kind for c in second.changes}
    assert kinds == {
        ChangeKind.HOST_UP,
        ChangeKind.HOST_DOWN,
        ChangeKind.PORT_OPENED,
        ChangeKind.SERVICE_CHANGED,
    }
    # INFO-level service change is filtered; the rest are alerted.
    assert {c.kind for c in notifier.sent[0][1]} == kinds - {ChangeKind.SERVICE_CHANGED}

    reg = monitor.metrics.registry
    assert reg.get_sample_value("netmon_hosts_up", {"job": "lab"}) == 2
    assert reg.get_sample_value("netmon_scans_total", {"job": "lab", "status": "succeeded"}) == 2
    assert "--unprivileged" in runner.calls[0] and runner.calls[0][-1] == "192.0.2.0/29"


async def test_transient_failure_is_retried(monitor_factory: Factory) -> None:
    runner = FakeRunner(NmapTimeout("slow"), fixture_xml("scan_baseline.xml"))
    outcome = await monitor_factory(runner).run_job(make_settings().job("lab"))
    assert outcome.status is ScanStatus.SUCCEEDED and len(runner.calls) == 2


async def test_permanent_failure_recorded(monitor_factory: Factory, storage: SQLiteStorage) -> None:
    runner = FakeRunner(NmapNotFound("no nmap"))
    outcome = await monitor_factory(runner).run_job(make_settings().job("lab"))
    assert outcome.status is ScanStatus.FAILED and len(runner.calls) == 1
    (scan,) = await storage.list_scans()
    assert scan["status"] == "failed" and "no nmap" in scan["error"]


async def test_exhausted_retries_and_bad_xml(monitor_factory: Factory) -> None:
    runner = FakeRunner(NmapFailed(1, "x"), NmapFailed(1, "y"), NmapFailed(1, "z"))
    assert (await monitor_factory(runner).run_job(make_settings().job("lab"))).status is (
        ScanStatus.FAILED
    )
    garbage = FakeRunner("<not-nmap/>")
    out = await monitor_factory(garbage).run_job(make_settings().job("lab"))
    assert out.status is ScanStatus.FAILED and "unexpected root" in out.reason


async def test_out_of_scope_job_refused_without_running(monitor_factory: Factory) -> None:
    settings = make_settings(jobs=[{"name": "bad", "targets": ["10.1.2.3"]}])
    runner = FakeRunner()
    outcome = await monitor_factory(runner, settings).run_job(settings.job("bad"))
    assert outcome.status is ScanStatus.REFUSED and runner.calls == []


async def test_outside_window_skipped(monitor_factory: Factory) -> None:
    settings = make_settings(
        policy={"scan_windows": [{"start": time(1), "end": time(2)}]},
    )
    runner = FakeRunner()
    outcome = await monitor_factory(runner, settings).run_job(
        settings.job("lab"), now=datetime(2026, 11, 9, 12, tzinfo=UTC)
    )
    assert outcome.status is ScanStatus.SKIPPED and runner.calls == []


async def test_incremental_scans_only_new_hosts(monitor_factory: Factory) -> None:
    settings = make_settings(
        jobs=[
            {"name": "lab", "targets": ["192.0.2.0/29"], "incremental": True, "profile": "services"}
        ]
    )
    runner = FakeRunner(
        fixture_xml("discovery.xml"),  # run 1: sweep
        fixture_xml("scan_baseline.xml"),  # run 1: both hosts are new -> port scan
        fixture_xml("discovery.xml"),  # run 2: sweep only; nothing stale
    )
    monitor = monitor_factory(runner, settings)
    job = settings.job("lab")

    await monitor.run_job(job)
    assert "-sn" in runner.calls[0]
    assert runner.calls[1][-2:] == ["192.0.2.10", "192.0.2.11"] and "-sV" in runner.calls[1]

    second = await monitor.run_job(job)
    assert len(runner.calls) == 3  # no port scan: hosts scanned < rescan_after ago
    assert second.changes == []  # services carried over -> no false "port closed"
