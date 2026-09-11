# Security policy

## What WireLens is (and is not)

WireLens is a **local** dashboard for **this computer’s** TCP/UDP sockets (`psutil`). By default it binds to **localhost only** (`127.0.0.1:8787`).

It is **not**:
- a cloud security product
- a perimeter firewall / IDS / IPS
- malware detection with verdicts
- a service that uploads your connection list to the publisher

Suspicion flags are **heuristic triage** with plain-English reasons (`GET /api/rules`). Treat them as hints, not proof.

## Trust checklist for users

1. Prefer downloading from this GitHub repository (or a Release you trust).
2. Read `start.bat` / `start-live.bat` and the Python entrypoints before first run.
3. Demo mode (`start.bat`) does not require admin; live mode sees real local sockets.
4. Default bind is localhost — do not expose the port to the internet unless you intentionally change that and understand the risk.
5. Optional Cash App tips are unrelated to runtime; the app does not phone home for payments.

## Reporting a vulnerability

Please **do not** open a public issue for security bugs.

Use GitHub’s **private vulnerability reporting** on this repository (Security tab → Report a vulnerability), or email the maintainer via the address on their GitHub profile if private reporting is unavailable.

Include:
- affected version / commit
- steps to reproduce
- impact (e.g. unintended network exposure, XSS in the local UI, path issues)

We will acknowledge reports and work a fix before any public write-up when practical.

## Supported versions

Only the latest `main` branch is supported for security fixes.
