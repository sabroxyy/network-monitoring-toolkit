# Security & compliance

Network scanning is legally sensitive and operationally risky. netmon is built to **fail
closed**: when it cannot prove a scan is allowed, it doesn't send packets.

## Authorization & consent

- **Only scan networks you own or have written permission to scan.** Unauthorised
  scanning may violate computer-misuse laws (e.g. CFAA, UK CMA) and provider ToS.
- `policy.authorization` records *who* approved scanning and *under which reference*
  (change ticket / contract). When `expires` passes, every job is skipped and
  `netmon_scans_total{status="skipped"}` increments — renewal is a deliberate act.
- Keep the approval artefact (ticket, signed scope) with the config in change control.
- For third-party / cloud ranges, check the provider's penetration-testing policy.

## Scope enforcement

- `policy.allowed_networks` is a hard allow-list; any target outside it is **refused**
  (`status=refused`) before nmap runs. Ranges broader than `/8` (IPv4) / `/32` (IPv6) are
  rejected at config load.
- Hostnames are off by default. With `allow_hostnames: true`, every resolved address must
  be in scope (prevents DNS-based scope escapes).
- Nmap ranges like `10.0.0.1-50` are not accepted — scope must be verifiable as CIDR.

## Opt-out

- `policy.exclude`: static excludes passed to nmap via `--exclude`.
- `policy.exclude_file`: re-read **before every scan**, so asset owners can opt out without
  a redeploy. A malformed file aborts the scan (a corrupt opt-out list must never widen
  scope); a missing file logs a warning.
- Publish how to request opt-out (e.g. a ticket queue) and record the ticket in the file
  comment.

## Scan windows & rate limits

- `scan_windows` (global or per job) with timezone and overnight wrap. Outside a window the
  job is skipped, not queued.
- `policy.max_rate` is a **global** packet-rate budget: each scan gets
  `max_rate / max_concurrent_scans`, so the aggregate never exceeds it.
- `-T5` (insane) is disallowed; default is `-T3`. `--host-timeout` and a whole-run
  `timeout` bound the blast radius of a slow target.
- Start with `discovery` and low `top_ports`; widen after confirming no impact on fragile
  devices (printers, PLCs/ICS, old embedded stacks). **Never** scan OT/ICS networks without
  the asset owner present.

## Privilege handling

- netmon **refuses to run as root** (`allow_root: false`).
- Default mode is unprivileged TCP connect scanning (`-sT --unprivileged`): no special
  rights needed.
- For SYN/UDP/OS detection set `nmap.privileged: true` and grant capabilities to the
  **nmap binary only**:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"
  ```
  The Docker image does this; start the container with `--cap-add NET_RAW --cap-add
  NET_ADMIN`. Note: file capabilities require `no-new-privileges` to be **off**; keep it on
  when running unprivileged.
- Anyone who can run that nmap can craft raw packets. Restrict execution, e.g.
  `chgrp netmon $(which nmap) && chmod 750 $(which nmap)`.

## Command & parser hardening

- nmap is executed via `create_subprocess_exec` — **never a shell** — with a scrubbed
  environment (`PATH`, `LANG`, `TZ`, …), its own process group, and a hard timeout.
- There is no free-form "extra args" option. Flags that read/write files or run code
  (`-iL`, `-oN/-oA`, `--script`, `--datadir`, `--resume`, `--stylesheet`) cannot be
  produced. Adding a flag requires a code change + review.
- Targets and port specs are regex-validated (no leading `-`, whitespace, metacharacters).
- XML is parsed with `defusedxml` — scan output contains attacker-controlled strings
  (banners, PTR names) and is treated as untrusted. XXE/entity expansion is rejected.

## Secrets management

- Config never contains secrets — only references: `env:NAME` or `file:/path`. Inline
  values are rejected at load.
- Preferred: mount secrets as files (Docker/Kubernetes secrets, systemd `LoadCredential=`,
  Vault Agent templates) and reference them with `file:`.
- Secrets are wrapped in `pydantic.SecretStr` (masked in reprs) and logs pass through a
  redaction filter (Slack webhook paths, `token=`, `password=`).
- Webhooks are HMAC-SHA256 signed over `timestamp.body`; receivers must verify and reject
  stale timestamps (see `examples/webhook_receiver.py`). Non-localhost webhooks must be
  HTTPS.
- The API (optional) is bearer-token protected, compares tokens in constant time, binds to
  `127.0.0.1` by default, and is read-only. Front it with TLS if exposed.
- Rotate tokens by updating the secret file and restarting; nothing is cached on disk.

## Data protection

The database is a map of your attack surface. Treat it as **confidential**:
restrict file permissions (`0600`, owned by `netmon`), encrypt the volume/backups, apply
retention (see `docs/operations.md`), and don't ship raw results to third-party SaaS
without review.

## Vulnerability disclosure

See [`SECURITY.md`](../SECURITY.md). If netmon reveals vulnerabilities in **third-party**
systems you're authorised to scan, follow coordinated disclosure: notify the owner
privately, give a reasonable fix window (commonly 90 days), and never publish target
details.
