# Operations

## Deployment options

### Docker (recommended)

```bash
docker build -t netmon .
docker run -d --name netmon --network host \
  --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
  --read-only --tmpfs /tmp \
  -v /etc/netmon/config.yaml:/etc/netmon/config.yaml:ro \
  -v netmon-data:/var/lib/netmon \
  netmon
```

- `--network host` is needed to see the LAN as the host does (ARP/MAC vendor). Without it
  you scan from the container network.
- Drop the `--cap-add` flags entirely if `nmap.privileged: false`.
- `deploy/docker-compose.yml` adds Prometheus with the alert rules in
  `deploy/prometheus/alerts.yml`.

### Bare metal / VM (systemd)

```bash
sudo python3 -m venv /opt/netmon/venv
sudo /opt/netmon/venv/bin/pip install .
sudo useradd --system --home /var/lib/netmon --create-home netmon
sudo install -d -o root -g netmon -m 750 /etc/netmon
sudo install -o root -g netmon -m 640 config/config.example.yaml /etc/netmon/config.yaml
sudo -u netmon /opt/netmon/venv/bin/netmon -c /etc/netmon/config.yaml validate
sudo cp deploy/systemd/netmon.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now netmon
```

### Kubernetes

Run as a single-replica `Deployment` (or one per network segment) with
`securityContext: {runAsNonRoot: true, capabilities: {drop: [ALL], add: [NET_RAW]}}`,
`hostNetwork: true` if scanning node-local networks, a `PersistentVolumeClaim` for
`/var/lib/netmon`, config in a `ConfigMap`, and secrets in `Secret` volumes referenced via
`file:`. **Do not run multiple replicas against one SQLite file.**

## Placement

Scan from where the threat is: a scanner inside each security zone sees what lateral
movement would see; one in the DMZ/internet sees external exposure. Use one netmon instance
per vantage point and label metrics via Prometheus `job`/`instance`.

## Runbook

| Symptom | Check |
|---|---|
| `NetmonScanStale` | `netmon scans --job X` → `error`; is it outside its window? auth expired? |
| `status=refused` | Target out of `allowed_networks`, or malformed opt-out file |
| `nmap exceeded timeout` | Lower `top_ports`, raise `timeout`, split targets into smaller jobs |
| Many `host_down` flaps | Hosts drop ICMP/probes; raise `alerting.cooldown`; consider adding a `-Pn` (skip host discovery) option for such jobs |
| `NmapFailed ... requires root` | `privileged: true` but nmap lacks caps / `no-new-privileges` set |

Ad-hoc commands:

```bash
netmon -c /etc/netmon/config.yaml validate            # show exact nmap argv per job
netmon -c /etc/netmon/config.yaml scan --job dmz-critical
netmon -c /etc/netmon/config.yaml changes --limit 20
netmon -c /etc/netmon/config.yaml history 192.0.2.10
```

## Backups & retention

SQLite in WAL mode supports online backups:

```bash
sqlite3 /var/lib/netmon/netmon.db ".backup '/backup/netmon-$(date +%F).db'"
```

Prune history periodically (cron / systemd timer):

```sql
DELETE FROM scans WHERE started_at < datetime('now', '-365 days');  -- cascades
DELETE FROM services WHERE scan_id IN
  (SELECT id FROM scans WHERE started_at < datetime('now', '-90 days'));
VACUUM;
```

## Upgrades & schema migrations

- Migrations are **forward-only**, numbered SQL files in `src/netmon/storage/migrations/`
  (`0002_add_x.sql`, …). They run automatically at start-up (or explicitly with
  `netmon migrate`) inside a transaction and are recorded in `schema_migrations`.
- Rules for authors: never edit a released migration; make changes additive
  (new nullable columns/tables) so the previous version can still run against the new
  schema during a rollout; do destructive clean-ups in a later release.
- Upgrade procedure:
  1. Back up the database.
  2. Read `CHANGELOG.md` for config changes; run `netmon validate` with the new version.
  3. Deploy; `netmon migrate` (or let `run` do it).
  4. Rollback = previous image + restored backup if a migration was not additive.
- Config is strict (`extra="forbid"`): unknown keys fail fast, so renamed options can't be
  silently ignored. Deprecations are announced one minor release ahead.
- Versioning follows SemVer; container tags `X.Y.Z` and `X.Y` are published by
  `.github/workflows/release.yml`.
