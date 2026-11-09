"""Build Nmap argv lists from validated job configuration.

There is intentionally **no** free-form ``extra_args`` escape hatch: flags such as
``-iL``, ``-oN``, ``--datadir``, ``--script`` or ``--resume`` can read/write arbitrary files
or execute code, so every supported option is modelled explicitly in :class:`Job`.
The command is always executed without a shell (see ``runner.py``).
"""

from __future__ import annotations

from collections.abc import Sequence

from netmon.config import Job, Nmap, Policy, Profile


class CommandError(ValueError):
    """The requested combination of options is unsafe or unsupported."""


def effective_rate(job: Job, policy: Policy) -> int:
    """Per-scan packet rate such that concurrent scans never exceed the global cap."""
    per_scan_cap = max(1, policy.max_rate // policy.max_concurrent_scans)
    return min(job.max_rate or per_scan_cap, per_scan_cap)


def build_command(
    job: Job,
    nmap: Nmap,
    policy: Policy,
    *,
    targets: Sequence[str] | None = None,
    excludes: Sequence[str] = (),
    profile: Profile | None = None,
) -> list[str]:
    profile = profile or job.profile
    scan_targets = list(targets if targets is not None else job.targets)
    if not scan_targets:
        raise CommandError("no targets to scan")
    if any(t.startswith("-") for t in scan_targets):  # defence in depth; config also checks
        raise CommandError("targets must not start with '-'")

    argv: list[str] = [
        nmap.path,
        "-oX",
        "-",  # XML to stdout; never write files
        "--noninteractive",
        f"-T{job.timing}",
        "--max-rate",
        str(effective_rate(job, policy)),
        "--max-retries",
        str(job.max_retries),
        "--host-timeout",
        f"{job.host_timeout}s",
        "--privileged" if nmap.privileged else "--unprivileged",
    ]
    if not job.resolve_dns:
        argv.append("-n")

    if profile == "discovery":
        argv.append("-sn")
    else:
        argv.append("-sS" if nmap.privileged else "-sT")
        if job.udp:
            if not nmap.privileged:
                raise CommandError("UDP scanning requires nmap.privileged (CAP_NET_RAW)")
            argv.append("-sU")
        if job.ports:
            argv += ["-p", job.ports]
        elif job.top_ports:
            argv += ["--top-ports", str(job.top_ports)]
        if profile == "services":
            argv += ["-sV", "--version-intensity", str(job.version_intensity)]
        if job.os_detection:
            if not nmap.privileged:
                raise CommandError("OS detection requires nmap.privileged (CAP_NET_RAW)")
            argv.append("-O")

    if excludes:
        argv += ["--exclude", ",".join(excludes)]
    argv += scan_targets
    return argv
