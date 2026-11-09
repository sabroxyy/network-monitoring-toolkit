"""Parse Nmap XML (``-oX``) into domain models.

Nmap has no native JSON output; XML is the stable, documented machine format
(https://nmap.org/book/output-formats-xml-output.html). We parse it with ``defusedxml``
to neutralise XXE and entity-expansion attacks — scan output is attacker-influenced
(banners, hostnames) and must be treated as untrusted input.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from netmon.models import Host, Service


class NmapParseError(ValueError):
    pass


@dataclass(slots=True)
class ParsedScan:
    hosts: list[Host] = field(default_factory=list)
    version: str | None = None
    args: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    summary: str | None = None
    exit_status: str | None = None


def _ts(value: str | None) -> datetime | None:
    return datetime.fromtimestamp(int(value), tz=UTC) if value and value.isdigit() else None


def _opt(el: Element | None, attr: str) -> str | None:
    if el is None:
        return None
    value = el.get(attr)
    return value or None


def _parse_service(port_el: Element) -> Service | None:
    state_el = port_el.find("state")
    portid, proto = port_el.get("portid"), port_el.get("protocol")
    if state_el is None or portid is None or proto is None:
        return None
    svc = port_el.find("service")
    return Service(
        port=int(portid),
        protocol=proto,
        state=state_el.get("state", "unknown"),
        name=_opt(svc, "name"),
        product=_opt(svc, "product"),
        version=_opt(svc, "version"),
        extra_info=_opt(svc, "extrainfo"),
        cpe=tuple(c.text for c in svc.findall("cpe") if c.text) if svc is not None else (),
    )


def _parse_host(el: Element) -> Host | None:
    address: str | None = None
    mac = vendor = None
    for addr in el.findall("address"):
        kind = addr.get("addrtype")
        if kind in ("ipv4", "ipv6") and address is None:
            address = addr.get("addr")
        elif kind == "mac":
            mac, vendor = addr.get("addr"), addr.get("vendor")
    if address is None:
        return None
    status_el = el.find("status")
    os_match = el.find("os/osmatch")
    services = [s for p in el.findall("ports/port") if (s := _parse_service(p))]
    return Host(
        address=address,
        status=status_el.get("state", "unknown") if status_el is not None else "unknown",
        hostnames=[n for h in el.findall("hostnames/hostname") if (n := h.get("name"))],
        mac=mac,
        vendor=vendor,
        os_guess=os_match.get("name") if os_match is not None else None,
        services=sorted(services, key=lambda s: (s.protocol, s.port)),
    )


def parse_nmap_xml(xml: str | bytes) -> ParsedScan:
    if not xml or not str(xml).strip():
        raise NmapParseError("empty nmap output")
    try:
        root = SafeET.fromstring(xml)
    except DefusedXmlException as exc:
        raise NmapParseError(f"refused unsafe XML: {exc}") from exc
    except SafeET.ParseError as exc:
        # Typically a truncated document from a killed/crashed nmap.
        raise NmapParseError(f"malformed nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapParseError(f"unexpected root element <{root.tag}>")

    finished = root.find("runstats/finished")
    return ParsedScan(
        hosts=[h for el in root.findall("host") if (h := _parse_host(el))],
        version=root.get("version"),
        args=root.get("args"),
        started_at=_ts(root.get("start")),
        finished_at=_ts(_opt(finished, "time")),
        summary=_opt(finished, "summary"),
        exit_status=_opt(finished, "exit"),
    )
