"""Change detection between the previous known state and a new scan.

The first scan of a job establishes a *baseline* and emits no changes, which avoids an
alert storm on day one. Severity rules are intentionally simple and easy to override.
"""

from __future__ import annotations

from collections.abc import Mapping

from netmon.models import Change, ChangeKind, Host, Severity

# Services that are commonly exploited or should rarely be exposed.
SENSITIVE_PORTS: frozenset[int] = frozenset(
    {21, 23, 135, 139, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
)


def _port_opened_severity(port: int) -> Severity:
    return Severity.CRITICAL if port in SENSITIVE_PORTS else Severity.WARNING


def diff_states(previous: Mapping[str, Host], current: Mapping[str, Host]) -> list[Change]:
    """Compare two ``{address: Host}`` snapshots containing only *up* hosts."""
    if not previous:
        return []
    changes: list[Change] = []

    for addr in sorted(current.keys() - previous.keys()):
        host = current[addr]
        ports = ", ".join(f"{p}/{proto}" for p, proto in sorted(host.open_services())) or "none"
        changes.append(
            Change(
                ChangeKind.HOST_UP,
                addr,
                Severity.WARNING,
                f"new host {addr} is up (open ports: {ports})",
            )
        )
    for addr in sorted(previous.keys() - current.keys()):
        changes.append(Change(ChangeKind.HOST_DOWN, addr, Severity.WARNING, f"host {addr} is down"))

    for addr in sorted(previous.keys() & current.keys()):
        before, after = previous[addr].open_services(), current[addr].open_services()
        for key in sorted(after.keys() - before.keys()):
            svc = after[key]
            changes.append(
                Change(
                    ChangeKind.PORT_OPENED,
                    addr,
                    _port_opened_severity(svc.port),
                    f"{addr}: port {svc.port}/{svc.protocol} opened ({svc.fingerprint})",
                    port=svc.port,
                    protocol=svc.protocol,
                    after=svc.fingerprint,
                )
            )
        for key in sorted(before.keys() - after.keys()):
            svc = before[key]
            changes.append(
                Change(
                    ChangeKind.PORT_CLOSED,
                    addr,
                    Severity.INFO,
                    f"{addr}: port {svc.port}/{svc.protocol} closed",
                    port=svc.port,
                    protocol=svc.protocol,
                    before=svc.fingerprint,
                )
            )
        for key in sorted(before.keys() & after.keys()):
            old, new = before[key], after[key]
            # Ignore changes where the new scan simply lacks version info (e.g. a
            # ports-only incremental pass after a services scan).
            if new.fingerprint == "unknown" or old.fingerprint == new.fingerprint:
                continue
            severity = Severity.WARNING if old.name != new.name else Severity.INFO
            changes.append(
                Change(
                    ChangeKind.SERVICE_CHANGED,
                    addr,
                    severity,
                    f"{addr}: {new.port}/{new.protocol} changed "
                    f"'{old.fingerprint}' -> '{new.fingerprint}'",
                    port=new.port,
                    protocol=new.protocol,
                    before=old.fingerprint,
                    after=new.fingerprint,
                )
            )
    return changes
