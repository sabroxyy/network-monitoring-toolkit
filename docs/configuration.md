# Configuration reference

Config is YAML, validated strictly (unknown keys are errors). Start from
[`config/config.example.yaml`](../config/config.example.yaml) and check it with
`netmon -c config.yaml validate`, which prints the exact nmap command for each job
without sending packets.

Durations accept seconds (`90`) or `30s`, `15m`, `2h`, `1d`.
Secret fields end in `_ref` and accept only `env:NAME` or `file:/path`.

## Top level

| Key | Default | Notes |
|---|---|---|
| `database` | `sqlite:////var/lib/netmon/netmon.db` | 4 slashes = absolute path |
| `allow_root` | `false` | Refuse to start as uid 0 |
| `nmap.path` | `nmap` | Binary name or path |
| `nmap.privileged` | `false` | `true` enables `-sS`, `-sU`, `-O`; needs `CAP_NET_RAW` on nmap |

## `policy`

| Key | Default | Notes |
|---|---|---|
| `allowed_networks` | **required** | CIDRs; every target must be inside one |
| `exclude` | `[]` | IPs/CIDRs → `--exclude` |
| `exclude_file` | none | Opt-out list, re-read every scan |
| `allow_hostnames` | `false` | Resolved IPs must be in scope |
| `scan_windows` | `[]` (any time) | List of `{days, start, end, timezone}` |
| `max_concurrent_scans` | `2` | Global semaphore |
| `max_rate` | `300` | Global packets/s, split across concurrent scans |
| `authorization` | **required** | `{owner, reference, expires?}` |

## `jobs[]`

| Key | Default | Notes |
|---|---|---|
| `name` | **required** | `[a-z0-9_-]`, unique; used as metric label |
| `targets` | **required** | IPs / CIDRs (hostnames if allowed) |
| `profile` | `ports` | `discovery` (`-sn`), `ports`, `services` (`-sV`) |
| `ports` | none | nmap `-p` spec; overrides `top_ports` |
| `top_ports` | `100` | `--top-ports N` |
| `udp` | `false` | `-sU`, requires privileged |
| `os_detection` | `false` | `-O`, requires privileged |
| `interval` / `jitter` | `1h` / `60s` | Next run = interval + U(0, jitter) |
| `timeout` | `30m` | Whole nmap run; process group is killed |
| `host_timeout` | `5m` | `--host-timeout` |
| `timing` | `3` | `-T0`..`-T4` (T5 refused) |
| `max_rate` | policy share | Capped by the global budget |
| `max_retries` | `2` | `--max-retries` (probe retransmissions) |
| `attempts` | `3` | Re-runs of a failed nmap invocation (exp. backoff + jitter) |
| `resolve_dns` | `false` | When false, passes `-n` |
| `version_intensity` | `5` | `--version-intensity` |
| `incremental` | `false` | Sweep, then only scan new/stale hosts |
| `rescan_after` | `24h` | Staleness threshold for incremental |
| `scan_windows` | inherit | `[]` = any time; overrides policy windows |
| `enabled` | `true` | |

## `alerting`

| Key | Default | Notes |
|---|---|---|
| `min_severity` | `warning` | `info` / `warning` / `critical` |
| `cooldown` | `1h` | Suppress identical alerts (flapping) |
| `channels` | `[]` | `slack`, `webhook`, `email` (see example config) |

Severity rules (`netmon/diff.py`): port opened on a sensitive port (RDP, SMB, Telnet,
databases, Docker API, …) → **critical**; other port opened, new host, host down, service
name change → **warning**; port closed or version change → **info**. The first scan of each
job is a silent baseline.

## `metrics`, `api`, `logging`

| Key | Default |
|---|---|
| `metrics.enabled/host/port` | `true` / `127.0.0.1` / `9105` |
| `api.enabled/host/port/token_ref` | `false` / `127.0.0.1` / `8080` / `env:NETMON_API_TOKEN` |
| `logging.level` / `logging.json` | `INFO` / `true` |

## Metrics

| Metric | Labels |
|---|---|
| `netmon_scans_total` | `job`, `status` (`succeeded/failed/skipped/refused`) |
| `netmon_scan_duration_seconds` (histogram) | `job` |
| `netmon_hosts_up`, `netmon_open_ports` | `job` |
| `netmon_changes_total` | `job`, `kind`, `severity` |
| `netmon_last_success_timestamp_seconds` | `job` |
| `netmon_alerts_total` | `channel`, `result` |

## API (optional, read-only)

`pip install 'netmon[api]'`, set `api.enabled: true` and `NETMON_API_TOKEN`.

| Endpoint | Auth |
|---|---|
| `GET /healthz` | none |
| `GET /v1/jobs`, `/v1/hosts`, `/v1/hosts/{addr}/history`, `/v1/changes?since=&limit=`, `/v1/scans?job=` | `Authorization: Bearer <token>` |
