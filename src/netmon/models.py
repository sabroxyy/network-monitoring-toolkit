"""Plain domain objects shared by the parser, diff engine, storage and alerting.

They are deliberately free of Nmap- and storage-specific details so each layer can be
tested (and swapped) independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class ScanStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"  # outside scan window, job disabled, authorization expired
    REFUSED = "refused"  # policy violation (target out of scope, bad opt-out file)


@dataclass(frozen=True, slots=True)
class Service:
    port: int
    protocol: str  # "tcp" | "udp" | "sctp"
    state: str  # "open" | "closed" | "filtered" | "open|filtered" ...
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    cpe: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[int, str]:
        return (self.port, self.protocol)

    @property
    def fingerprint(self) -> str:
        """Human-readable service identity used to detect version drift."""
        parts = [p for p in (self.name, self.product, self.version) if p]
        return " ".join(parts) or "unknown"


@dataclass(slots=True)
class Host:
    address: str
    status: str  # "up" | "down"
    hostnames: list[str] = field(default_factory=list)
    mac: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    services: list[Service] = field(default_factory=list)

    def open_services(self) -> dict[tuple[int, str], Service]:
        return {s.key: s for s in self.services if s.state == "open"}


@dataclass(slots=True)
class ScanResult:
    job: str
    targets: list[str]
    started_at: datetime
    finished_at: datetime
    commands: list[list[str]]
    hosts: list[Host] = field(default_factory=list)
    nmap_version: str | None = None
    summary: str | None = None

    @property
    def duration_s(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def up_hosts(self) -> dict[str, Host]:
        return {h.address: h for h in self.hosts if h.status == "up"}


class ChangeKind(StrEnum):
    HOST_UP = "host_up"
    HOST_DOWN = "host_down"
    PORT_OPENED = "port_opened"
    PORT_CLOSED = "port_closed"
    SERVICE_CHANGED = "service_changed"


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Change:
    kind: ChangeKind
    host: str
    severity: Severity
    message: str
    port: int | None = None
    protocol: str | None = None
    before: str | None = None
    after: str | None = None
