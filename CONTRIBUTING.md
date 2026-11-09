# Contributing

```bash
python -m venv .venv && . .venv/bin/activate
make install        # editable install with dev + api extras, pre-commit hooks
make check          # ruff format --check, ruff lint, mypy --strict, pytest + coverage
make test-unit      # skip tests that need a real nmap binary
```

Ground rules:

- **Type hints everywhere**; `mypy --strict` must pass.
- **Tests with every change.** Unit tests use `tests/conftest.py::FakeRunner` with XML
  fixtures in `tests/fixtures/` — no network access. Integration tests (`-m integration`)
  only scan `127.0.0.1`.
- **New nmap options** must be modelled as typed `Job` fields in `config.py`, emitted in
  `scanner/command.py`, covered by `tests/unit/test_command.py`, and reviewed against
  `docs/security.md`. Free-form argument passthrough will not be accepted.
- **Schema changes** = a new numbered file in `src/netmon/storage/migrations/`. Never edit
  a released migration. Keep migrations additive.
- Never commit real IPs, hostnames, scan output or secrets. Use RFC 5737
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example.test` in fixtures.
- Conventional commit messages are appreciated (`feat:`, `fix:`, `docs:` …); update
  `CHANGELOG.md`.
