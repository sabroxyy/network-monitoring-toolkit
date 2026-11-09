"""Typed configuration loaded from YAML.

Secrets are never stored in the config file itself. Any field ending in ``_ref`` holds a
*reference* resolved at runtime by :func:`resolve_secret`:

* ``env:NAME``   -> value of environment variable ``NAME``
* ``file:/path`` -> contents of a file (e.g. a Docker/Kubernetes secret mount)
"""

from __future__ import annotations

import ipaddress
import os
import re
from datetime import date, datetime, time
from pathlib import Path
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from netmon.models import Severity

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class ConfigError(ValueError):
    """Raised for invalid or unsafe configuration."""


def parse_duration(value: Any) -> int:
    """Parse ``90``, ``"90s"``, ``"15m"``, ``"2h"`` or ``"1d"`` into seconds."""
    if isinstance(value, bool):
        raise ValueError("duration must be a number or string like '15m'")
    if isinstance(value, int | float):
        return int(value)
    if isinstance(value, str) and (m := _DURATION_RE.match(value)):
        return int(m.group(1)) * _UNITS[m.group(2)]
    raise ValueError(f"invalid duration {value!r}; use e.g. 30s, 15m, 2h, 1d")


def _duration(v: Any) -> int:
    seconds = parse_duration(v)
    if seconds <= 0:
        raise ValueError("duration must be positive")
    return seconds


Duration = Annotated[int, BeforeValidator(_duration)]


def resolve_secret(ref: str | None) -> SecretStr | None:
    """Resolve an ``env:`` / ``file:`` secret reference. Literal values are rejected."""
    if not ref:
        return None
    scheme, _, target = ref.partition(":")
    if scheme == "env":
        value = os.environ.get(target)
        if value is None:
            raise ConfigError(f"secret environment variable {target!r} is not set")
        return SecretStr(value)
    if scheme == "file":
        try:
            return SecretStr(Path(target).read_text(encoding="utf-8").strip())
        except OSError as exc:
            raise ConfigError(f"cannot read secret file {target!r}: {exc}") from exc
    raise ConfigError("secret references must use 'env:NAME' or 'file:/path' (no inline secrets)")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- scan windows
class ScanWindow(_Strict):
    """A recurring window during which scanning is permitted. Supports overnight wrap."""

    days: list[str] = Field(default_factory=lambda: list(_DAYS))
    start: time
    end: time
    timezone: str = "UTC"

    @field_validator("days")
    @classmethod
    def _days(cls, v: list[str]) -> list[str]:
        days = [d.lower()[:3] for d in v]
        if bad := [d for d in days if d not in _DAYS]:
            raise ValueError(f"unknown day(s): {bad}")
        return days

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        ZoneInfo(v)  # raises on unknown zone
        return v

    def contains(self, moment: datetime) -> bool:
        local = moment.astimezone(ZoneInfo(self.timezone))
        t, day = local.time(), _DAYS[local.weekday()]
        if self.start <= self.end:
            return day in self.days and self.start <= t < self.end
        # Overnight window (e.g. 22:00-06:00): the early-morning part belongs to the
        # window that *started* the previous day.
        if t >= self.start:
            return day in self.days
        prev_day = _DAYS[(local.weekday() - 1) % 7]
        return t < self.end and prev_day in self.days


# --------------------------------------------------------------------------- policy
class Authorization(_Strict):
    """Documented consent for scanning. Scans are refused once ``expires`` has passed."""

    owner: str
    reference: str = Field(description="Ticket / change-request / contract ID")
    expires: date | None = None


class Policy(_Strict):
    allowed_networks: list[str] = Field(
        min_length=1, description="Every target must fall inside one of these CIDRs."
    )
    exclude: list[str] = Field(default_factory=list, description="Opt-out IPs/CIDRs")
    exclude_file: Path | None = Field(
        default=None, description="Opt-out list re-read before every scan (one IP/CIDR per line)"
    )
    allow_hostnames: bool = False
    scan_windows: list[ScanWindow] = Field(default_factory=list)
    max_concurrent_scans: int = Field(default=2, ge=1, le=32)
    max_rate: int = Field(default=300, ge=1, le=10_000, description="Global packets/s cap")
    authorization: Authorization

    @field_validator("allowed_networks", "exclude")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        for item in v:
            ipaddress.ip_network(item, strict=False)
        return v

    @field_validator("allowed_networks")
    @classmethod
    def _not_internet(cls, v: list[str]) -> list[str]:
        for item in v:
            net = ipaddress.ip_network(item, strict=False)
            if net.prefixlen < (8 if net.version == 4 else 32):
                raise ValueError(f"{item} is too broad; split it into smaller allowed ranges")
        return v


# --------------------------------------------------------------------------- jobs
Profile = Literal["discovery", "ports", "services"]
_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:/]*$")
_PORTS_RE = re.compile(r"^[TUS:0-9,\-]+$")


class Job(_Strict):
    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_\-]{0,62}$")]
    targets: list[str] = Field(min_length=1)
    profile: Profile = "ports"
    ports: str | None = Field(default=None, description="Nmap -p spec, e.g. '22,80,443,8000-8100'")
    top_ports: int | None = Field(default=100, ge=1, le=65535)
    udp: bool = False
    interval: Duration = 3600
    jitter: Duration = 60
    timeout: Duration = 1800
    host_timeout: Duration = 300
    timing: int = Field(default=3, ge=0, le=4, description="Nmap -T template; T5 is disallowed")
    max_rate: int | None = Field(default=None, ge=1, le=10_000)
    max_retries: int = Field(default=2, ge=0, le=10, description="Nmap probe retransmissions")
    resolve_dns: bool = False
    os_detection: bool = False
    version_intensity: int = Field(default=5, ge=0, le=9)
    incremental: bool = Field(
        default=False,
        description="Ping-sweep first, then port-scan only live hosts that are new or stale",
    )
    rescan_after: Duration = 86400
    attempts: int = Field(default=3, ge=1, le=10, description="Retries of a failed nmap run")
    scan_windows: list[ScanWindow] | None = None
    enabled: bool = True

    @field_validator("targets")
    @classmethod
    def _targets(cls, v: list[str]) -> list[str]:
        for t in v:
            # Rejects option injection ("-iL /etc/shadow"), whitespace and shell metachars.
            if not _TARGET_RE.match(t):
                raise ValueError(f"invalid target {t!r}")
        return v

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: str | None) -> str | None:
        if v is not None and not _PORTS_RE.match(v):
            raise ValueError(f"invalid port specification {v!r}")
        return v

    @model_validator(mode="after")
    def _consistency(self) -> Job:
        if self.profile != "discovery" and self.ports:
            object.__setattr__(self, "top_ports", None)  # explicit ports win
        if self.os_detection and self.profile == "discovery":
            raise ValueError("os_detection requires a port profile")
        return self


# --------------------------------------------------------------------------- alerting
class SlackChannel(_Strict):
    type: Literal["slack"]
    webhook_url_ref: str


class WebhookChannel(_Strict):
    type: Literal["webhook"]
    url: str
    hmac_secret_ref: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def _https(cls, v: str) -> str:
        if not v.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise ValueError("webhook URLs must use https (plain http allowed only for localhost)")
        return v


class EmailChannel(_Strict):
    type: Literal["email"]
    smtp_host: str
    smtp_port: int = 587
    starttls: bool = True
    sender: str
    recipients: list[str] = Field(min_length=1)
    username_ref: str | None = None
    password_ref: str | None = None


Channel = Annotated[SlackChannel | WebhookChannel | EmailChannel, Field(discriminator="type")]


class Alerting(_Strict):
    min_severity: Severity = Severity.WARNING
    cooldown: Duration = 3600
    channels: list[Channel] = Field(default_factory=list)


# --------------------------------------------------------------------------- runtime
class Nmap(_Strict):
    path: str = "nmap"
    privileged: bool = Field(
        default=False,
        description="Use raw-socket scans (-sS). Requires CAP_NET_RAW on the nmap binary, "
        "never running netmon itself as root.",
    )


class Metrics(_Strict):
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = Field(default=9105, ge=1, le=65535)


class Api(_Strict):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    token_ref: str | None = "env:NETMON_API_TOKEN"  # noqa: S105 - a reference, not a secret


class Logging(_Strict):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    json_format: bool = Field(default=True, alias="json")


class Settings(_Strict):
    database: str = Field(default="sqlite:////var/lib/netmon/netmon.db")
    allow_root: bool = False
    nmap: Nmap = Nmap()
    policy: Policy
    jobs: list[Job] = Field(min_length=1)
    alerting: Alerting = Alerting()
    metrics: Metrics = Metrics()
    api: Api = Api()
    logging: Logging = Logging()

    @model_validator(mode="after")
    def _unique_jobs(self) -> Settings:
        names = [j.name for j in self.jobs]
        if dupes := {n for n in names if names.count(n) > 1}:
            raise ValueError(f"duplicate job names: {sorted(dupes)}")
        return self

    def job(self, name: str) -> Job:
        for j in self.jobs:
            if j.name == name:
                return j
        raise ConfigError(f"no such job: {name!r}")


def load_settings(path: str | Path) -> Settings:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot load config {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")
    try:
        return Settings.model_validate(raw)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
