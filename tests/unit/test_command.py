from __future__ import annotations

import pytest

from netmon.config import Job, Nmap, Policy
from netmon.scanner.command import CommandError, build_command, effective_rate

POLICY = Policy.model_validate(
    {
        "allowed_networks": ["192.0.2.0/24"],
        "max_rate": 300,
        "max_concurrent_scans": 3,
        "authorization": {"owner": "o", "reference": "r"},
    }
)


def test_unprivileged_services_command() -> None:
    job = Job(name="j", targets=["192.0.2.0/29"], profile="services", top_ports=50)
    argv = build_command(job, Nmap(), POLICY, excludes=["192.0.2.5"])
    assert argv[:3] == ["nmap", "-oX", "-"]
    assert "--unprivileged" in argv and "-sT" in argv and "-sS" not in argv
    assert argv[argv.index("--top-ports") + 1] == "50"
    assert "-sV" in argv and "-n" in argv
    assert argv[argv.index("--exclude") + 1] == "192.0.2.5"
    assert argv[argv.index("--max-rate") + 1] == "100"  # 300 / 3 concurrent
    assert argv[-1] == "192.0.2.0/29"


def test_privileged_discovery_and_options() -> None:
    job = Job(name="j", targets=["192.0.2.1"], profile="discovery", resolve_dns=True)
    argv = build_command(job, Nmap(privileged=True), POLICY)
    assert "-sn" in argv and "--privileged" in argv
    assert "-n" not in argv and "-sS" not in argv


def test_explicit_ports_udp_os() -> None:
    job = Job(name="j", targets=["192.0.2.1"], ports="22,53,U:161", udp=True, os_detection=True)
    argv = build_command(job, Nmap(privileged=True), POLICY)
    assert argv[argv.index("-p") : argv.index("-p") + 2] == ["-p", "22,53,U:161"]
    assert "-sU" in argv and "-O" in argv and "--top-ports" not in argv


@pytest.mark.parametrize("field", ["udp", "os_detection"])
def test_raw_socket_features_require_privilege(field: str) -> None:
    job = Job(name="j", targets=["192.0.2.1"], **{field: True})
    with pytest.raises(CommandError, match="privileged"):
        build_command(job, Nmap(), POLICY)


def test_target_override_and_injection_guard() -> None:
    job = Job(name="j", targets=["192.0.2.0/29"])
    assert build_command(job, Nmap(), POLICY, targets=["192.0.2.3"])[-1] == "192.0.2.3"
    with pytest.raises(CommandError):
        build_command(job, Nmap(), POLICY, targets=["-iL/etc/passwd"])
    with pytest.raises(CommandError):
        build_command(job, Nmap(), POLICY, targets=[])


def test_effective_rate_honours_job_and_global_caps() -> None:
    assert effective_rate(Job(name="j", targets=["192.0.2.1"], max_rate=10), POLICY) == 10
    assert effective_rate(Job(name="j", targets=["192.0.2.1"], max_rate=5000), POLICY) == 100


def test_no_dangerous_flags_ever_emitted() -> None:
    job = Job(name="j", targets=["192.0.2.1"], profile="services")
    argv = build_command(job, Nmap(privileged=True), POLICY)
    for flag in ("-iL", "-oN", "-oA", "--script", "--datadir", "--resume", "-T5"):
        assert flag not in argv
