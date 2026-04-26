# Security policy

The full RackWatch security policy lives at
[rackwatch.io/security.html](https://rackwatch.io/security.html). This file
is the GitHub-conventional pointer for the `rackwatch-agent` repository.

## Reporting a vulnerability

- **Private GitHub advisory:** open one at
  https://github.com/rackwatch/rackwatch-agent/security/advisories/new
- **Email:** security@rackwatch.io — request a PGP key in your initial
  message and we'll respond with one before you send details.

You can expect:
- Acknowledgement within 48 hours.
- Initial triage and severity assessment within 7 days.
- Coordinated disclosure target within 90 days (sooner for critical
  issues, longer if architectural changes are required — we'll
  communicate either way).

## Scope

In scope:
- Privilege escalation in the agent's install path or runtime
- Agent-to-platform auth (`AGENT_API_KEY` handling)
- Tampering with collected telemetry before transmission
- Path traversal, command injection, or deserialization in any agent
  collector

Out of scope:
- Findings that require root access on a host already running the
  agent as root
- Self-DoS through misconfiguration
- Vulnerabilities in third-party dependencies that are already patched
  in a current release

## Build provenance

- Source: this repository, tagged per release.
- Build: GitHub Actions on `release/*` tags. Workflow definition in
  [.github/workflows/release.yml](.github/workflows/release.yml).
- Artifacts: SHA-256 of each released binary is published in the
  GitHub release notes.
- Reproducible builds: target. Not yet claiming reproducibility for
  the .NET self-contained output. Status is tracked in
  [rackwatch.io/security.html](https://rackwatch.io/security.html).

## Supported versions

Only the latest minor version receives security fixes during the 0.x
series. Once 1.0 ships, we'll publish a support window for prior minor
versions here.

## Acknowledgements

Reporters credited in release notes unless they prefer to remain
anonymous. No paid bounty yet — early-stage product — but we send
merch and a public thank-you for any report that leads to a fix.
