from __future__ import annotations

import pytest

from netmon.scanner.parser import NmapParseError, parse_nmap_xml
from tests.conftest import fixture_xml


def test_parse_baseline() -> None:
    scan = parse_nmap_xml(fixture_xml("scan_baseline.xml"))
    assert scan.version == "7.94"
    assert scan.summary and "2 hosts up" in scan.summary
    assert scan.started_at and scan.finished_at and scan.finished_at > scan.started_at
    web, other = scan.hosts
    assert web.address == "192.0.2.10"
    assert web.mac == "00:11:22:33:44:55" and web.vendor == "Acme Networks"
    assert web.hostnames == ["web01.example.test"]
    assert web.os_guess == "Linux 5.0 - 5.14"
    ssh = web.services[0]
    assert (ssh.port, ssh.protocol, ssh.state) == (22, "tcp", "open")
    assert ssh.fingerprint == "ssh OpenSSH 8.9p1"
    assert ssh.cpe == ("cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel")
    assert set(other.open_services()) == {(80, "tcp")}  # filtered 8080 excluded


def test_parse_real_nmap_output() -> None:
    scan = parse_nmap_xml(fixture_xml("nmap_localhost_real.xml"))
    (host,) = scan.hosts
    assert host.address == "127.0.0.1" and host.status == "up"
    assert {s.port: s.state for s in host.services} == {18080: "open", 18081: "closed"}
    assert host.services[0].product == "SimpleHTTPServer"


def test_discovery_has_no_services() -> None:
    scan = parse_nmap_xml(fixture_xml("discovery.xml"))
    assert [h.address for h in scan.hosts] == ["192.0.2.10", "192.0.2.11"]
    assert all(not h.services for h in scan.hosts)


def test_rejects_xxe() -> None:
    with pytest.raises(NmapParseError, match="unsafe"):
        parse_nmap_xml(fixture_xml("malicious_xxe.xml"))


@pytest.mark.parametrize("doc", ["", "   ", "<other/>", fixture_xml("truncated.xml")])
def test_rejects_garbage(doc: str) -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(doc)
