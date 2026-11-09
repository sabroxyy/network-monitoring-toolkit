from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from netmon.diff import diff_states
from netmon.models import ScanResult, ScanStatus
from netmon.scanner.parser import parse_nmap_xml
from netmon.storage import open_storage
from netmon.storage.sqlite import SQLiteStorage, available_migrations
from tests.conftest import fixture_xml

T0 = datetime(2026, 11, 9, 12, tzinfo=UTC)


def result(name: str, at: datetime) -> ScanResult:
    hosts = parse_nmap_xml(fixture_xml(name)).hosts
    return ScanResult("lab", ["192.0.2.0/29"], at, at + timedelta(seconds=10), [["nmap"]], hosts)


async def test_migrations_idempotent(storage: SQLiteStorage) -> None:
    assert await storage.migrate() == []  # already applied by fixture
    assert available_migrations()[0][0] == 1


async def test_full_roundtrip(storage: SQLiteStorage) -> None:
    r1 = result("scan_baseline.xml", T0)
    sid = await storage.start_scan("lab", ["nmap"], T0)
    state1 = r1.up_hosts()
    await storage.complete_scan(sid, r1, state1, state1.keys(), [])

    loaded = await storage.load_state("lab")
    assert set(loaded) == {"192.0.2.10", "192.0.2.11"}
    assert loaded["192.0.2.10"].services == state1["192.0.2.10"].services  # incl. cpe tuple

    r2 = result("scan_changed.xml", T0 + timedelta(hours=1))
    changes = diff_states(loaded, r2.up_hosts())
    sid2 = await storage.start_scan("lab", ["nmap"], r2.started_at)
    await storage.complete_scan(sid2, r2, r2.up_hosts(), ["192.0.2.10"], changes)

    hosts = {h["address"]: h for h in await storage.list_hosts()}
    assert set(hosts) == {"192.0.2.10", "192.0.2.11", "192.0.2.12"}
    assert hosts["192.0.2.10"]["mac"] == "00:11:22:33:44:55"  # preserved via COALESCE
    assert hosts["192.0.2.10"]["first_seen"] < hosts["192.0.2.10"]["last_seen"]

    stored = await storage.list_changes()
    assert len(stored) == len(changes) == 4
    assert await storage.list_changes(since=T0 + timedelta(days=1)) == []

    scans = await storage.list_scans("lab")
    assert [s["status"] for s in scans] == ["succeeded", "succeeded"]
    assert scans[0]["hosts_up"] == 2

    last = await storage.last_port_scans("lab")
    assert set(last) == {"192.0.2.10"}  # .12 was not port-scanned in run 2

    history = await storage.host_history("192.0.2.10")
    assert {h["port"] for h in history} == {22, 443, 3389}


async def test_fail_scan(storage: SQLiteStorage) -> None:
    sid = await storage.start_scan("lab", ["nmap"], T0)
    await storage.fail_scan(sid, ScanStatus.FAILED, "boom", T0)
    (scan,) = await storage.list_scans()
    assert scan["status"] == "failed" and scan["error"] == "boom"


async def test_file_backed_storage(tmp_path: object) -> None:
    s = open_storage(f"sqlite:///{tmp_path}/sub/netmon.db")
    assert await s.migrate() == [1]
    await s.close()


def test_open_storage_rejects_unknown() -> None:
    with pytest.raises(NotImplementedError):
        open_storage("postgresql://localhost/netmon")
    with pytest.raises(ValueError):
        open_storage("mysql://x")
