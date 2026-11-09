# network-monitoring-toolkit — `netmon`

Safe, scheduled network monitoring built on **Nmap** and **Python**: discovery, port,
service and version detection on a schedule, change detection with severities, alerts
(Slack / signed webhook / email), history in SQL and a Prometheus exporter.

It is designed for small teams that want something **reliable, auditable and hard to
misuse**:

- **Fails closed.** Every target is checked against an allow-list of networks, an opt-out
  list, scan windows and an expiring authorization record before a packet is sent.
- **No shell, no free-form flags.** Nmap is invoked as an argv list from typed config;
  output is parsed with `defusedxml`.
- **Non-root by default.** TCP connect scans need no privileges; raw-socket scans use
  `CAP_NET_RAW` on the nmap binary only.
- **Quiet by design.** First scan is a silent baseline; afterwards you're told only what
  changed, with cooldown against flapping.

```
nmap ──XML──▶ parse ──▶ diff vs. last state ──▶ SQLite history ──▶ alerts + /metrics
  ▲
  └── scheduler (intervals, jitter, windows, concurrency & rate budget) ◀── policy
```

## Quick start

Requirements: Python ≥ 3.11 and `nmap` on `PATH` (`apt install nmap` / `brew install nmap`).

```bash
git clone https://github.com/sabroxyy/network-monitoring-toolkit.git
cd network-monitoring-toolkit
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
```

Try it on your own machine (scans only `127.0.0.1`):

```bash
python examples/minimal_scan.py
```

```text
run 1: succeeded
  127.0.0.1 8000/tcp http SimpleHTTPServer 0.6
Start/stop a service on 127.0.0.1:8000-8100, then press Enter...
run 2: succeeded
  [warning] 127.0.0.1: port 8081/tcp opened (http SimpleHTTPServer 0.6)
```

## Configure

```bash
cp config/config.example.yaml config.yaml   # edit allowed_networks, jobs, authorization
netmon -c config.yaml validate              # prints exact nmap argv per job; sends nothing
```

A minimal config:

```yaml
database: sqlite:///netmon.db
policy:
  allowed_networks: [192.0.2.0/24]          # hard scope
  exclude: [192.0.2.1]                       # opt-out
  scan_windows:
    - {days: [mon, tue, wed, thu, fri], start: "19:00", end: "07:00", timezone: UTC}
  max_rate: 300                              # global packets/s
  authorization: {owner: netops@example.com, reference: CHG-42, expires: 2027-12-31}
jobs:
  - {name: lan-discovery, targets: [192.0.2.0/24], profile: discovery, interval: 15m}
  - name: lan-services
    targets: [192.0.2.0/24]
    profile: services
    top_ports: 200
    incremental: true          # sweep, then only re-scan new/stale hosts
    interval: 1h
alerting:
  channels:
    - {type: slack, webhook_url_ref: env:NETMON_SLACK_WEBHOOK}   # secrets by reference only
```

Full reference: [docs/configuration.md](docs/configuration.md).

## Run

```bash
netmon -c config.yaml scan --job lan-services   # one-off run (still policy-checked)
netmon -c config.yaml run                       # scheduler daemon + metrics on :9105
netmon -c config.yaml changes --limit 20        # recent changes (JSON)
netmon -c config.yaml history 192.0.2.10        # per-port history of a host
```

Docker:

```bash
docker build -t netmon .
docker run -d --network host --cap-drop ALL \
  -v "$PWD/config.yaml:/etc/netmon/config.yaml:ro" -v netmon-data:/var/lib/netmon netmon
# add --cap-add NET_RAW --cap-add NET_ADMIN only if nmap.privileged: true
```

`deploy/docker-compose.yml` brings up netmon + Prometheus with ready-made alert rules.

## Repository layout

```
src/netmon/
  config.py            typed YAML config, durations, scan windows, secret refs
  policy.py            scope / opt-out / windows / authorization (fail closed)
  scanner/command.py   allow-listed nmap argv builder + rate budgeting
  scanner/runner.py    asyncio subprocess: timeout, scrubbed env, process-group kill
  scanner/parser.py    defusedxml → Host/Service models
  diff.py              baseline + change detection with severities
  service.py           one job run: policy → nmap → parse → diff → store → alert → metrics
  scheduler.py         per-job asyncio loops, jitter, global concurrency limit
  storage/             Storage protocol, SQLite backend, numbered SQL migrations
  alerting/            Slack, HMAC webhook, email; severity filter, cooldown, retries
  metrics.py           Prometheus exporter
  cli.py / api.py      CLI and optional read-only FastAPI
tests/
  unit/                fast, no network (FakeRunner + XML fixtures)
  integration/         real nmap against 127.0.0.1 only
  fixtures/            sanitised nmap XML (RFC 5737 addresses), XXE/truncated samples
config/                example config + opt-out file
deploy/                docker-compose, Prometheus config & alert rules, systemd unit
docs/                  architecture, security, operations, configuration
examples/              minimal scanner, webhook signature verifier
.github/               CI (lint, mypy, tests ×3 Pythons, pip-audit, Docker + Trivy), release
```

## Development

```bash
make check        # ruff format/lint + mypy --strict + pytest with coverage gate (80%)
make test-unit    # skip tests that need a real nmap binary
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Design rationale (why direct subprocess instead of
python-nmap/libnmap, why asyncio, incremental scanning, storage options) is in
[docs/architecture.md](docs/architecture.md). Deployment, runbook, backups and the
upgrade/migration strategy are in [docs/operations.md](docs/operations.md).

## Responsible use

Only scan networks you own or are explicitly authorised to test. Read
[docs/security.md](docs/security.md) before pointing netmon at production, and report
vulnerabilities in netmon itself via [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
