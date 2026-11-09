# Architecture

## Goals

| Objective | How netmon delivers it |
|---|---|
| Active discovery | `discovery` profile (`nmap -sn`) on a short interval |
| Port / service / version detection | `ports` (`-sT`/`-sS`) and `services` (`-sV`) profiles, optional `-O` |
| Periodic scans | asyncio scheduler, per-job interval + jitter, scan windows |
| Alerting | Change detection → severity → Slack / webhook (HMAC) / email |
| Historical state | Immutable per-scan observations + current per-job state in SQL |
| Observability | Prometheus metrics, structured JSON logs, optional read-only API |

## Data flow

```
             ┌────────────┐
 config.yaml │  Settings  │  pydantic: strict, typed, secret *references* only
             └─────┬──────┘
                   ▼
 ┌───────────┐  ┌──────────────┐   ┌───────────────┐   ┌──────────────┐
 │ Scheduler │─▶│ PolicyEngine │──▶│ build_command │──▶│  NmapRunner  │── nmap -oX - …
 │ (asyncio) │  │ scope/window │   │ argv, no shell│   │ timeout/kill │
 └───────────┘  │ opt-out/auth │   └───────────────┘   └──────┬───────┘
   semaphore    └──────────────┘                              │ XML (untrusted)
   + jitter                                                   ▼
                ┌────────────┐    ┌──────────┐        ┌───────────────┐
                │  Storage   │◀───│   diff   │◀───────│ parse (defused│
                │ (1 txn)    │    │ prev→cur │        │   xml)        │
                └────────────┘    └────┬─────┘        └───────────────┘
                                       ▼
                         ┌──────────────────────────┐    ┌──────────┐
                         │ AlertDispatcher          │    │ Metrics  │
                         │ severity filter/cooldown │    │ /metrics │
                         └──────────────────────────┘    └──────────┘
```

`service.Monitor.run_job()` is the whole pipeline for one run; the scheduler only decides
*when*. That split makes the pipeline trivially testable (inject a `FakeRunner`) and lets the
CLI `scan` command reuse it.

## Module map

| Module | Responsibility |
|---|---|
| `config.py` | YAML → typed `Settings`; durations, windows, secret refs, validation |
| `policy.py` | Fail-closed guard-rails: scope, opt-out, windows, authorization expiry |
| `scanner/command.py` | Allow-listed argv construction, per-scan rate budgeting |
| `scanner/runner.py` | `asyncio` subprocess, scrubbed env, timeout, process-group kill |
| `scanner/parser.py` | `defusedxml` parser → `Host`/`Service` models |
| `diff.py` | Baseline + change detection with severities |
| `storage/` | `Storage` protocol, SQLite backend, numbered SQL migrations |
| `alerting/` | Notifiers (Slack/webhook/email) + dispatcher (filter, cooldown, retry) |
| `metrics.py` | Prometheus collectors on an isolated registry |
| `scheduler.py` | Per-job loops, global semaphore, graceful stop |
| `service.py` | Pipeline orchestration, incremental scanning |
| `runtime.py` | Object-graph wiring shared by CLI/API/examples |
| `cli.py`, `api.py` | Entry points |

## Technology choices

**Direct subprocess + own XML parser instead of `python-nmap` / `libnmap`.**
Both libraries ultimately shell out to nmap and parse XML. Owning that ~150 lines buys:
- an explicit flag allow-list (python-nmap accepts a free-form `arguments` string — an
  injection footgun);
- native `asyncio` with hard timeouts and process-group kill on cancel;
- `defusedxml` hardening (scan output contains attacker-controlled banners/hostnames);
- no dependency on lightly-maintained packages.
`libnmap` remains a reasonable choice if you need its `NmapReport.diff()`; swap it in behind
`parse_nmap_xml()` without touching anything else.

**asyncio, not multiprocessing.** Every hot path is I/O-bound: waiting on nmap (which is
itself massively parallel), HTTP, and SQLite (run in a worker thread). One event loop with a
semaphore gives bounded concurrency with no IPC or pickling. Use multiple *scanner
instances* (one per network segment / vantage point) to scale horizontally instead.

**XML, not JSON.** Nmap has no native JSON output; `-oX` is the stable, documented machine
format. We normalise to our own models and persist JSON columns where useful.

## Incremental scanning

With `incremental: true`, each run does:
1. a cheap ping sweep (`-sn`) of all targets → live set;
2. a port/service scan of only those live hosts that are **new** or whose last port scan is
   older than `rescan_after`;
3. hosts not rescanned keep their previously known services (so no false "port closed").

This cuts scan traffic by an order of magnitude on stable networks while still detecting
new hosts every interval. Full detail is refreshed on the `rescan_after` cadence.

## Storage

Schema (`storage/migrations/0001_initial.sql`):

| Table | Purpose | Retention suggestion |
|---|---|---|
| `scans` | One row per run: status, argv (audit), duration, error | 1 year |
| `observations` | Host status per scan (immutable history) | 90 days |
| `services` | Port/service/version per host per scan (immutable history) | 90 days |
| `hosts` | Inventory: first/last seen, MAC/vendor/OS (latest non-null) | forever |
| `host_state` | Current per-job snapshot that the next scan is diffed against | n/a |
| `changes` | Detected changes with severity | 1 year |

**Backends.** SQLite (WAL) is the default and is right for a single scanner node up to tens
of thousands of hosts. For multi-node or long retention, implement `Storage` in
`storage/postgres.py` (the SQL is portable; swap `AUTOINCREMENT` for `BIGSERIAL`, `TEXT`
timestamps for `TIMESTAMPTZ`, JSON `TEXT` for `JSONB`). For time-series dashboards, don't
write to InfluxDB directly — scrape the Prometheus exporter (or use remote-write into
Influx/Mimir/Thanos); the SQL store remains the system of record for per-port history.

## Extension points

- **New alert channel**: implement the `Notifier` protocol (`name`, `async send()`), add a
  config model to the `Channel` union, wire it in `build_notifiers()`.
- **New storage backend**: implement `Storage`, register a URL scheme in `open_storage()`.
- **Custom severity rules**: edit `diff.SENSITIVE_PORTS` or post-process `diff_states()`.
- **NSE scripts**: deliberately unsupported. If needed, add an explicit `scripts` field
  restricted to the `safe` category and review per `docs/security.md`.
