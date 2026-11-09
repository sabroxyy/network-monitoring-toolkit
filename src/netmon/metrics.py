"""Prometheus metrics. Uses a dedicated registry so tests stay isolated."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, start_http_server


class Metrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        r = self.registry
        self.scans_total = Counter(
            "netmon_scans_total", "Scan runs by outcome", ["job", "status"], registry=r
        )
        self.scan_duration = Histogram(
            "netmon_scan_duration_seconds",
            "Wall-clock duration of nmap runs",
            ["job"],
            buckets=(5, 15, 30, 60, 120, 300, 600, 1200, 1800, 3600),
            registry=r,
        )
        self.hosts_up = Gauge(
            "netmon_hosts_up", "Hosts up in the latest state", ["job"], registry=r
        )
        self.open_ports = Gauge(
            "netmon_open_ports", "Open ports across hosts in the latest state", ["job"], registry=r
        )
        self.changes_total = Counter(
            "netmon_changes_total", "Detected changes", ["job", "kind", "severity"], registry=r
        )
        self.last_success = Gauge(
            "netmon_last_success_timestamp_seconds",
            "Unix time of the last successful scan",
            ["job"],
            registry=r,
        )
        self.alerts_total = Counter(
            "netmon_alerts_total", "Alert deliveries", ["channel", "result"], registry=r
        )

    def serve(self, host: str, port: int) -> None:
        start_http_server(port, addr=host, registry=self.registry)
