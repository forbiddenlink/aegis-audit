# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Baseline diffing** (`--baseline PATH`, `--update-baseline`): record the
  current findings and, on later runs, report and gate only on findings that are
  new since the baseline. Baselines store opaque fingerprints (rule + location +
  description, line-number independent), never finding text or evidence.
- Config models reject unknown keys (`extra="forbid"`). A typo such as
  `allowlist_urls` (the real field is `scope.allow`) now raises at load time
  instead of being silently dropped and leaving the scanner running with
  permissive defaults.
- Test coverage for the CI gate, scan-history store, Notion sink, alert
  webhooks, and the scan orchestrator.

### Security

- The Docker image runs as an unprivileged `appuser` rather than root, so a
  parser or dependency bug cannot escalate to a container escape.
- Documented the SSRF guard's residual DNS-rebinding TOCTOU (host is validated
  by resolution, then re-resolved by the HTTP client at connect time) as a
  tracked, accepted limitation pending transport-level IP pinning.

## [0.1.0] - Unreleased

First alpha. Security posture reports for a deployed site (`scan`) and a source
tree (`audit`), producing one score, one CI exit code, and JSON / SARIF 2.1.0 /
HTML reports.

### Added

- **`scan`** — passive checks against a live URL: security headers, HTTPS and
  mixed content, TLS certificate expiry and protocol version, DNS (SPF, DMARC,
  CAA), Subresource Integrity and outdated JS libraries, passive PII/secret
  detection, and optional `.env` / `.git` probing (`--probe`).
- **`audit`** — static analysis of a local tree: hardcoded secrets, vulnerable
  Python dependencies (`pip-audit`) and Node dependencies (`npm audit`), and
  dangerous Python patterns (`eval` / `exec`).
- **CI gate** — `--fail-on <severity>` and `--fail-under <score>` with exit
  codes following the semgrep / osv-scanner convention (0 clean, 1 gate tripped,
  ≥2 tool error).
- **Reports** — JSON, SARIF 2.1.0 for GitHub code scanning, and a self-contained
  HTML report with a trend chart backed by a local SQLite history.
- **Alerts** — optional Slack / Discord / Telegram / Notion delivery, restricted
  to an allowlist of known hosts.
- An SSRF guard applied to the initial URL and re-applied to every redirect hop,
  blocking private, loopback, link-local, and cloud-metadata destinations.
- A `.aegisignore` for excluding test fixtures and docs from secret scanning.

[Unreleased]: https://github.com/forbiddenlink/aegis-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/forbiddenlink/aegis-audit/releases/tag/v0.1.0
