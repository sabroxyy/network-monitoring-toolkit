from __future__ import annotations

from netmon.diff import diff_states
from netmon.models import ChangeKind, Severity
from netmon.scanner.parser import parse_nmap_xml
from tests.conftest import fixture_xml


def up(name: str) -> dict:  # type: ignore[type-arg]
    return {h.address: h for h in parse_nmap_xml(fixture_xml(name)).hosts if h.status == "up"}


def test_first_scan_is_baseline() -> None:
    assert diff_states({}, up("scan_baseline.xml")) == []


def test_no_changes_when_identical() -> None:
    assert diff_states(up("scan_baseline.xml"), up("scan_baseline.xml")) == []


def test_detects_all_change_kinds() -> None:
    changes = diff_states(up("scan_baseline.xml"), up("scan_changed.xml"))
    by_kind = {(c.kind, c.host, c.port): c for c in changes}

    assert (ChangeKind.HOST_UP, "192.0.2.12", None) in by_kind
    assert (ChangeKind.HOST_DOWN, "192.0.2.11", None) in by_kind
    rdp = by_kind[(ChangeKind.PORT_OPENED, "192.0.2.10", 3389)]
    assert rdp.severity is Severity.CRITICAL  # RDP is on the sensitive list
    ssh = by_kind[(ChangeKind.SERVICE_CHANGED, "192.0.2.10", 22)]
    assert ssh.before == "ssh OpenSSH 8.9p1" and ssh.after == "ssh OpenSSH 9.6p1"
    assert ssh.severity is Severity.INFO
    assert len(changes) == 4


def test_port_closed_and_unknown_fingerprint_ignored() -> None:
    before = up("scan_baseline.xml")
    after = up("scan_baseline.xml")
    web = after["192.0.2.10"]
    # Ports-only rescan: same ports, no version data -> no SERVICE_CHANGED noise.
    web.services = [
        type(s)(port=s.port, protocol=s.protocol, state=s.state) for s in web.services[:1]
    ]
    changes = diff_states(before, after)
    assert [(c.kind, c.port) for c in changes] == [(ChangeKind.PORT_CLOSED, 443)]
