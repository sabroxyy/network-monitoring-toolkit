"""The scan pipeline for a single job run:

policy check -> build argv -> run nmap (retry/backoff) -> parse -> merge state -> diff
-> persist (one transaction) -> alert -> metrics.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from netmon.alerting import AlertDispatcher
from netmon.config import Job, Settings
from netmon.diff import diff_states
from netmon.metrics import Metrics
from netmon.models import Change, Host, ScanResult, ScanStatus
from netmon.policy import PolicyEngine, PolicyViolation
from netmon.retry import retry_async
from netmon.scanner import NmapError, Runner, build_command, parse_nmap_xml
from netmon.scanner.parser import ParsedScan
from netmon.storage import Storage

log = logging.getLogger(__name__)


@dataclass(slots=True)
class RunOutcome:
    job: str
    status: ScanStatus
    scan_id: int | None = None
    changes: list[Change] = field(default_factory=list)
    alerted: list[Change] = field(default_factory=list)
    reason: str = ""


def ensure_not_root(settings: Settings) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0 and not settings.allow_root:
        raise PermissionError(
            "refusing to run as root; grant CAP_NET_RAW to the nmap binary instead "
            "(see docs/security.md) or set allow_root: true"
        )


class Monitor:
    def __init__(
        self,
        settings: Settings,
        storage: Storage,
        runner: Runner,
        dispatcher: AlertDispatcher,
        metrics: Metrics,
        policy: PolicyEngine | None = None,
        retry_base_delay: float = 5.0,
    ) -> None:
        self.settings = settings
        self.storage = storage
        self.runner = runner
        self.dispatcher = dispatcher
        self.metrics = metrics
        self.policy = policy or PolicyEngine(settings.policy)
        self._retry_base_delay = retry_base_delay

    async def _nmap(self, job: Job, argv: list[str]) -> ParsedScan:
        async def once() -> ParsedScan:
            return parse_nmap_xml(await self.runner.run(argv, timeout=job.timeout))

        return await retry_async(
            once,
            attempts=job.attempts,
            base_delay=self._retry_base_delay,
            should_retry=lambda e: isinstance(e, NmapError) and e.transient,
            description=f"nmap job {job.name}",
        )

    async def run_job(self, job: Job, *, now: datetime | None = None) -> RunOutcome:
        decision = self.policy.check(job, now)
        if not decision.allowed:
            log.info("skipping job %s: %s", job.name, decision.reason, extra={"job": job.name})
            self.metrics.scans_total.labels(job=job.name, status=ScanStatus.SKIPPED).inc()
            return RunOutcome(job.name, ScanStatus.SKIPPED, reason=decision.reason)

        started = datetime.now(UTC)
        t0 = time.monotonic()
        try:
            targets = self.policy.validate_targets(job.targets)
            excludes = self.policy.exclusions()
        except PolicyViolation as exc:
            log.error("scan refused by policy: %s", exc, extra={"job": job.name})
            self.metrics.scans_total.labels(job=job.name, status=ScanStatus.REFUSED).inc()
            return RunOutcome(job.name, ScanStatus.REFUSED, reason=str(exc))
        nmap_cfg, pol = self.settings.nmap, self.settings.policy
        first_profile = "discovery" if job.incremental else job.profile
        argv = build_command(
            job, nmap_cfg, pol, targets=targets, excludes=excludes, profile=first_profile
        )
        scan_id = await self.storage.start_scan(job.name, argv, started)
        log.info("scan started", extra={"job": job.name, "scan_id": scan_id})

        try:
            previous = await self.storage.load_state(job.name)
            parsed = await self._nmap(job, argv)
            commands = [argv]
            current = {h.address: h for h in parsed.hosts if h.status == "up"}
            port_scanned: set[str] = set(current) if job.profile != "discovery" else set()

            if job.incremental and job.profile != "discovery":
                stale = await self._select_stale(job, current, started)
                port_scanned = set(stale)
                # Hosts not re-scanned keep their previously known services.
                for addr, host in current.items():
                    if addr not in stale and addr in previous:
                        host.services = previous[addr].services
                if stale:
                    argv2 = build_command(
                        job, nmap_cfg, pol, targets=sorted(stale), excludes=excludes
                    )
                    commands.append(argv2)
                    detail = await self._nmap(job, argv2)
                    for h in detail.hosts:
                        if h.address in current:
                            current[h.address].services = h.services
                            current[h.address].os_guess = h.os_guess or current[h.address].os_guess
        except (NmapError, ValueError) as exc:
            await self.storage.fail_scan(scan_id, ScanStatus.FAILED, str(exc), datetime.now(UTC))
            self.metrics.scans_total.labels(job=job.name, status=ScanStatus.FAILED).inc()
            log.error("scan failed: %s", exc, extra={"job": job.name, "scan_id": scan_id})
            return RunOutcome(job.name, ScanStatus.FAILED, scan_id, reason=str(exc))

        finished = datetime.now(UTC)
        result = ScanResult(
            job=job.name,
            targets=targets,
            started_at=started,
            finished_at=finished,
            commands=commands,
            hosts=list(current.values()),
            nmap_version=parsed.version,
            summary=parsed.summary,
        )
        changes = diff_states(previous, current)
        await self.storage.complete_scan(scan_id, result, current, port_scanned, changes)
        alerted = await self.dispatcher.dispatch(job.name, changes)

        m = self.metrics
        m.scans_total.labels(job=job.name, status=ScanStatus.SUCCEEDED).inc()
        m.scan_duration.labels(job=job.name).observe(time.monotonic() - t0)
        m.hosts_up.labels(job=job.name).set(len(current))
        m.open_ports.labels(job=job.name).set(sum(len(h.open_services()) for h in current.values()))
        m.last_success.labels(job=job.name).set(finished.timestamp())
        for ch in changes:
            m.changes_total.labels(job=job.name, kind=ch.kind, severity=ch.severity).inc()
        log.info(
            "scan finished: %d hosts up, %d changes, %d alerted",
            len(current),
            len(changes),
            len(alerted),
            extra={"job": job.name, "scan_id": scan_id},
        )
        return RunOutcome(job.name, ScanStatus.SUCCEEDED, scan_id, changes, alerted)

    async def _select_stale(self, job: Job, live: dict[str, Host], now: datetime) -> list[str]:
        last = await self.storage.last_port_scans(job.name)
        cutoff = now - timedelta(seconds=job.rescan_after)
        return sorted(a for a in live if a not in last or last[a] < cutoff)
