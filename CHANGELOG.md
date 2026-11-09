# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/),
versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-09
### Added
- Initial scaffold: typed YAML config, fail-closed scan policy (scope, opt-out file,
  scan windows, authorization expiry, global rate budget).
- Allow-listed nmap argv builder; asyncio runner with timeout, scrubbed env and
  process-group kill; `defusedxml` XML parser.
- Change detection (host up/down, port opened/closed, service changed) with severities and
  silent baseline; incremental scanning.
- SQLite storage with forward-only migrations; Slack, HMAC-signed webhook and email alerts
  with cooldown and retries; Prometheus metrics; optional read-only FastAPI.
- CLI (`validate`, `scan`, `run`, `migrate`, `hosts`, `changes`, `scans`, `history`),
  Dockerfile, docker-compose + Prometheus alert rules, systemd unit, GitHub Actions CI.
