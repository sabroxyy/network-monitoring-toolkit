from __future__ import annotations

from datetime import UTC, date, datetime, time
from pathlib import Path

import pytest

from netmon.config import Job, Policy, ScanWindow
from netmon.policy import PolicyEngine, PolicyViolation


def policy(**kw: object) -> Policy:
    base: dict[str, object] = {
        "allowed_networks": ["192.0.2.0/24", "2001:db8::/48"],
        "authorization": {"owner": "netops", "reference": "CHG-1"},
    }
    return Policy.model_validate({**base, **kw})


def test_targets_in_scope() -> None:
    engine = PolicyEngine(policy())
    assert engine.validate_targets(["192.0.2.0/28", "192.0.2.5", "2001:db8::1"])


@pytest.mark.parametrize("target", ["192.0.3.1", "192.0.0.0/16", "10.0.0.1", "2001:db9::1"])
def test_targets_out_of_scope(target: str) -> None:
    with pytest.raises(PolicyViolation, match="outside"):
        PolicyEngine(policy()).validate_targets([target])


def test_hostnames_need_opt_in_and_resolve_in_scope() -> None:
    with pytest.raises(PolicyViolation, match="allow_hostnames"):
        PolicyEngine(policy()).validate_targets(["web.example.test"])

    engine = PolicyEngine(policy(allow_hostnames=True), resolver=lambda h: ["192.0.2.7"])
    assert engine.validate_targets(["web.example.test"]) == ["web.example.test"]

    evil = PolicyEngine(policy(allow_hostnames=True), resolver=lambda h: ["192.0.2.7", "8.8.8.8"])
    with pytest.raises(PolicyViolation):
        evil.validate_targets(["web.example.test"])

    def boom(h: str) -> list[str]:
        raise OSError("NXDOMAIN")

    with pytest.raises(PolicyViolation, match="resolve"):
        PolicyEngine(policy(allow_hostnames=True), resolver=boom).validate_targets(["x.test"])


def test_exclusions_merge_opt_out_file(tmp_path: Path) -> None:
    f = tmp_path / "optout.txt"
    f.write_text("# owners who opted out\n192.0.2.50  # printer\n\n192.0.2.64/28\n")
    engine = PolicyEngine(policy(exclude=["192.0.2.1"], exclude_file=f))
    assert engine.exclusions() == ["192.0.2.1", "192.0.2.50", "192.0.2.64/28"]


def test_corrupt_opt_out_file_fails_closed(tmp_path: Path) -> None:
    f = tmp_path / "optout.txt"
    f.write_text("not-an-ip\n")
    with pytest.raises(PolicyViolation):
        PolicyEngine(policy(exclude_file=f)).exclusions()


def test_missing_opt_out_file_is_tolerated(tmp_path: Path) -> None:
    engine = PolicyEngine(policy(exclude_file=tmp_path / "nope.txt"))
    assert engine.exclusions() == []


def test_check_window_and_authorization() -> None:
    win = ScanWindow(start=time(22), end=time(6))
    engine = PolicyEngine(
        policy(
            scan_windows=[win.model_dump()],
            authorization={"owner": "x", "reference": "CHG-2", "expires": "2026-12-31"},
        )
    )
    job = Job(name="j", targets=["192.0.2.1"])
    assert engine.check(job, datetime(2026, 11, 9, 23, tzinfo=UTC)).allowed
    d = engine.check(job, datetime(2026, 11, 9, 12, tzinfo=UTC))
    assert not d.allowed and "window" in d.reason
    expired = engine.check(job, datetime(2027, 1, 1, 23, tzinfo=UTC))
    assert not expired.allowed and "expired" in expired.reason
    assert engine.authorization_valid(date(2026, 12, 31)).allowed

    # Job-level windows override global ones; disabled jobs never run.
    anytime = Job(name="k", targets=["192.0.2.1"], scan_windows=[])
    assert engine.check(anytime, datetime(2026, 11, 9, 12, tzinfo=UTC)).allowed
    off = Job(name="m", targets=["192.0.2.1"], enabled=False)
    assert engine.check(off).reason == "job disabled"
