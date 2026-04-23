# Security Policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's **Private Vulnerability Reporting** for this repository:

1. Go to the repo's **Security** tab
2. Click **Report a vulnerability**
3. Fill in the form — description, reproduction steps, impact assessment,
   the commit SHA you tested against, and optionally your preferred
   disclosure name

The report stays private between you and the maintainers until we agree
on a coordinated disclosure timeline. No email address to memorise, no
PGP-key hand-off, no "did the mail arrive?" uncertainty.

You will receive an acknowledgement within **72 hours**. We aim to
respond with a timeline within **7 days** and have a fix released
within **30 days** for high-severity issues.

## Scope

In scope:

- The gateway service itself (this repository)
- The default Docker configuration and deployment artefacts
- Any dependency pinning / build-time integrity issues

Out of scope (report to the respective vendor):

- Vulnerabilities in GitHub OAuth / GitHub itself
- Vulnerabilities in Caddy, WireGuard, or other upstream projects
- Social-engineering attacks against individual maintainers
- Denial-of-service via resource exhaustion (see Threat Model below —
  DoS is explicitly out of scope for this tool)

## Threat model

This project's security model is documented in [README.md](README.md)
under "Security model & caveats." Vulnerability reports that rely on
assumptions outside the documented threat model (e.g. an attacker who
already has root on the gateway VM, an admin intentionally misusing
their privileges) will be acknowledged but may not result in a fix.

## Coordinated disclosure

We ask that reporters:

1. Give us a reasonable window (minimum 30 days, negotiable) to develop
   and release a fix before public disclosure.
2. Avoid testing against production deployments you don't own. Test
   against a local clone — `docker compose up --build` is all it takes.
3. Do not exfiltrate any data beyond what's necessary to demonstrate
   the vulnerability.

In exchange, we will:

1. Keep you updated on our progress via the private advisory thread.
2. Credit you publicly in the release notes (with your consent).
3. Not pursue legal action against good-faith security research
   conducted within these guidelines.

## Supported versions

Only the `main` branch is actively maintained. Deployments should
track main and rebuild regularly. There are no LTS branches.
