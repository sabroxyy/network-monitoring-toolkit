# Security policy

## Reporting a vulnerability in netmon

Please **do not** open a public issue. Report privately via
[GitHub Security Advisories](../../security/advisories/new) for this repository.

Include: affected version/commit, a description, reproduction steps, and impact. We aim to
acknowledge within **3 business days**, provide a triage assessment within **10 business
days**, and ship a fix or mitigation within **90 days** (sooner for critical issues). We'll
credit reporters who wish to be named once a fix is released.

In scope: command/argument injection into nmap, scope-enforcement bypasses, parser
issues (XXE, DoS), secret leakage, API authentication flaws, container privilege issues.

## Supported versions

Only the latest minor release receives security fixes during 0.x.

## Responsible use

netmon is a tool for monitoring networks you own or are **authorised** to test. See
[docs/security.md](docs/security.md) for safe-scanning practices and guidance on
disclosing issues you find in third-party systems.
