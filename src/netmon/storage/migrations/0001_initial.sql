-- netmon schema v1. Portable SQL (SQLite + PostgreSQL) except where noted.
-- Timestamps are ISO-8601 UTC strings for SQLite; use TIMESTAMPTZ on PostgreSQL.

CREATE TABLE scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,   -- PG: BIGSERIAL PRIMARY KEY
    job           TEXT    NOT NULL,
    status        TEXT    NOT NULL,                    -- running|succeeded|failed|skipped
    started_at    TEXT    NOT NULL,
    finished_at   TEXT,
    command       TEXT    NOT NULL,                    -- JSON argv, for auditability
    nmap_version  TEXT,
    hosts_up      INTEGER,
    summary       TEXT,
    error         TEXT
);
CREATE INDEX ix_scans_job_started ON scans (job, started_at DESC);

-- Inventory: one row per address ever seen.
CREATE TABLE hosts (
    address     TEXT PRIMARY KEY,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    hostnames   TEXT NOT NULL DEFAULT '[]',            -- JSON array
    mac         TEXT,
    vendor      TEXT,
    os_guess    TEXT
);

-- Immutable history: what each scan observed.
CREATE TABLE observations (
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    address   TEXT    NOT NULL,
    status    TEXT    NOT NULL,
    PRIMARY KEY (scan_id, address)
);

CREATE TABLE services (
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    address     TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    protocol    TEXT    NOT NULL,
    state       TEXT    NOT NULL,
    name        TEXT,
    product     TEXT,
    version     TEXT,
    extra_info  TEXT,
    cpe         TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (scan_id, address, port, protocol)
);
CREATE INDEX ix_services_addr ON services (address, port);

-- Current known state per job (what the next scan is diffed against).
CREATE TABLE host_state (
    job             TEXT NOT NULL,
    address         TEXT NOT NULL,
    status          TEXT NOT NULL,
    services        TEXT NOT NULL DEFAULT '[]',        -- JSON array of Service
    last_seen       TEXT NOT NULL,
    last_port_scan  TEXT,
    PRIMARY KEY (job, address)
);

CREATE TABLE changes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    job          TEXT NOT NULL,
    detected_at  TEXT NOT NULL,
    kind         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    host         TEXT NOT NULL,
    port         INTEGER,
    protocol     TEXT,
    before       TEXT,
    after        TEXT,
    message      TEXT NOT NULL
);
CREATE INDEX ix_changes_detected ON changes (detected_at DESC);
CREATE INDEX ix_changes_host ON changes (host);
