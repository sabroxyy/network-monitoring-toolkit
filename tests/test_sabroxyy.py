"""Tests for sabroxyy.py. Run with:  python3 -m pytest -q"""

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sabroxyy as s  # noqa: E402

SAMPLE_XML = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.94">
  <host><status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <hostnames><hostname name="server.lan"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"/></port>
      <port protocol="tcp" portid="3389"><state state="open"/>
        <service name="ms-wbt-server"/></port>
      <port protocol="tcp" portid="80"><state state="closed"/></port>
      <port protocol="tcp" portid="9999"><state state="open"/></port>
    </ports>
    <os><osmatch name="Linux 5.X"/></os>
  </host>
  <host><status state="down"/><address addr="192.0.2.11" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="192.0.2.12" addrtype="ipv4"/><ports/></host>
</nmaprun>
"""


# ---------------------------------------------------------------- targets
@pytest.mark.parametrize(
    "text",
    ["192.168.1.10", "192.168.1.0/24", "10.0.0.0/16", "192.168.1.1-50", "router.lan", "::1"],
)
def test_valid_targets(text: str) -> None:
    assert s.validate_targets(text) == [text]


def test_several_targets() -> None:
    assert s.validate_targets("192.168.1.1, 192.168.1.2") == ["192.168.1.1", "192.168.1.2"]


@pytest.mark.parametrize(
    "text",
    ["", "-iL /etc/passwd", "1.1.1.1; rm -rf /", "$(whoami)", "10.0.0.0/8", "1.2.3.4/99"],
)
def test_invalid_targets(text: str) -> None:
    with pytest.raises(ValueError):
        s.validate_targets(text)


# ---------------------------------------------------------------- ports & options
def test_ports() -> None:
    assert s.validate_ports("22, 80,443") == "22,80,443"
    assert s.validate_ports("1-1024") == "1-1024"
    for bad in ("abc", "22;id", "0", "70000", "-p 22"):
        with pytest.raises(ValueError):
            s.validate_ports(bad)


def test_default_choice() -> None:
    assert [o.flag for o in s.parse_choices("")] == ["-sT", "-F", "-sV"]


def test_choices_with_commas_and_duplicates() -> None:
    assert [o.flag for o in s.parse_choices("3,9,3")] == ["-sS", "-O"]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("2 3", "only one"),  # -sT and -sS
        ("5 6", "only one"),  # -F and -p-
        ("1 8", "can't be combined"),  # -sn with -sV
        ("99", "not an option"),
        ("x", "not an option"),
    ],
)
def test_bad_choices(text: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        s.parse_choices(text)


def test_build_command() -> None:
    opts = s.parse_choices("2 7 8")
    cmd = s.build_command(opts, ["192.168.1.0/24"], "22,80")
    assert cmd == ["nmap", "-sT", "-p", "22,80", "-sV", "192.168.1.0/24"]
    with pytest.raises(ValueError):
        s.build_command(opts, ["192.168.1.1"])  # option 7 without ports


def test_every_option_is_documented() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    for o in s.OPTIONS:
        assert f"`{o.flag}`" in readme, f"{o.flag} missing from README"


# ---------------------------------------------------------------- risk & parsing
def test_classify_port() -> None:
    assert s.classify_port(3389)[0] == s.CRITICAL
    assert s.classify_port(22)[0] == s.MEDIUM
    assert s.classify_port(443)[0] == s.LOW
    assert s.classify_port(12345) == s.UNKNOWN_RISK


def test_parse_nmap_xml() -> None:
    hosts = s.parse_nmap_xml(SAMPLE_XML)
    assert [h.address for h in hosts] == ["192.0.2.10", "192.0.2.12"]  # down host skipped
    server = hosts[0]
    assert server.hostname == "server.lan" and server.os_guess == "Linux 5.X"
    assert [(p.port, p.risk) for p in server.ports] == [
        (22, s.MEDIUM),
        (3389, s.CRITICAL),
        (9999, s.LOW),
    ]  # closed port 80 skipped
    assert server.ports[0].version == "OpenSSH 9.6"


def test_report() -> None:
    report = s.render_report(s.parse_nmap_xml(SAMPLE_XML), ["nmap", "x"], color=False)
    assert "1 CRITICAL" in report and "1 MEDIUM" in report and "1 LOW" in report
    assert "Remote Desktop (RDP)" in report
    assert "no open ports found" in report  # host .12
    assert "\033[" not in report  # no colour codes in saved files
    empty = s.render_report([], ["nmap", "x"], color=False)
    assert "No hosts are up" in empty


# ---------------------------------------------------------------- command line
def test_root_needed_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(s, "is_root", lambda: False)
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/nmap")
    assert s.main(["-t", "127.0.0.1", "-o", "3", "-y"]) == 1
    assert "sudo python3 sabroxyy.py" in capsys.readouterr().out


def test_bad_target_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/nmap")
    assert s.main(["-t", "-iL x", "-o", "2", "-y"]) == 2


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed")
def test_real_scan_of_localhost(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert s.main(["-t", "127.0.0.1", "-o", "2,7,12", "-p", "1", "-y", "-s"]) == 0
    (report,) = (tmp_path / "reports").glob("scan_*.txt")
    assert "Host: 127.0.0.1" in report.read_text()
