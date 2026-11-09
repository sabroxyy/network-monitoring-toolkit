"""Safety guard-rails evaluated *before* any packet leaves the box.

The policy engine is the single place that decides whether a job may run, and against
which addresses. It fails closed: anything it cannot verify is refused.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime

from netmon.config import Job, Policy, ScanWindow

log = logging.getLogger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], list[str]]


class PolicyViolation(PermissionError):
    """A scan was refused by policy. Never retried."""


def system_resolver(hostname: str) -> list[str]:
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    return sorted({str(info[4][0]) for info in infos})


def _networks(items: Iterable[str]) -> list[IPNetwork]:
    return [ipaddress.ip_network(i.strip(), strict=False) for i in items if i.strip()]


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str = ""


class PolicyEngine:
    def __init__(self, policy: Policy, resolver: Resolver = system_resolver) -> None:
        self.policy = policy
        self._allowed = _networks(policy.allowed_networks)
        self._resolver = resolver

    # ------------------------------------------------------------------ exclusions
    def exclusions(self) -> list[str]:
        """Static excludes plus the opt-out file, re-read on every call."""
        items = list(self.policy.exclude)
        path = self.policy.exclude_file
        if path is not None:
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    entry = line.split("#", 1)[0].strip()
                    if entry:
                        ipaddress.ip_network(entry, strict=False)  # validate
                        items.append(entry)
            except FileNotFoundError:
                log.warning("opt-out file %s not found; using static excludes only", path)
            except ValueError as exc:
                # A corrupt opt-out list must never silently widen scope.
                raise PolicyViolation(f"invalid entry in opt-out file {path}: {exc}") from exc
        return items

    # ------------------------------------------------------------------ scope
    def _in_scope(self, net: IPNetwork) -> bool:
        return any(
            net.version == allowed.version and net.subnet_of(allowed)  # type: ignore[arg-type]
            for allowed in self._allowed
        )

    def validate_targets(self, targets: Iterable[str]) -> list[str]:
        """Return the targets unchanged if *all* are in scope, else raise."""
        validated: list[str] = []
        for target in targets:
            try:
                nets = [ipaddress.ip_network(target, strict=False)]
            except ValueError:
                if not self.policy.allow_hostnames:
                    raise PolicyViolation(
                        f"target {target!r} is not an IP/CIDR and allow_hostnames is false"
                    ) from None
                try:
                    resolved = self._resolver(target)
                except OSError as exc:
                    raise PolicyViolation(f"cannot resolve {target!r}: {exc}") from exc
                if not resolved:
                    raise PolicyViolation(f"{target!r} resolved to no addresses") from None
                nets = _networks(resolved)
            for net in nets:
                if not self._in_scope(net):
                    raise PolicyViolation(f"target {target!r} ({net}) is outside allowed_networks")
            validated.append(target)
        return validated

    # ------------------------------------------------------------------ time
    def windows_for(self, job: Job) -> list[ScanWindow]:
        return job.scan_windows if job.scan_windows is not None else self.policy.scan_windows

    def in_window(self, job: Job, now: datetime | None = None) -> bool:
        windows = self.windows_for(job)
        if not windows:
            return True
        moment = now or datetime.now(UTC)
        return any(w.contains(moment) for w in windows)

    def authorization_valid(self, today: date | None = None) -> Decision:
        auth = self.policy.authorization
        today = today or datetime.now(UTC).date()
        if auth.expires is not None and today > auth.expires:
            return Decision(False, f"scan authorization {auth.reference} expired on {auth.expires}")
        return Decision(True)

    # ------------------------------------------------------------------ combined
    def check(self, job: Job, now: datetime | None = None) -> Decision:
        """Non-raising check used by the scheduler to decide run vs. skip."""
        if not job.enabled:
            return Decision(False, "job disabled")
        auth = self.authorization_valid(now.date() if now else None)
        if not auth.allowed:
            return auth
        if not self.in_window(job, now):
            return Decision(False, "outside scan window")
        return Decision(True)
