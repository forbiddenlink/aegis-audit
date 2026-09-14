# AegisAudit 🛡️

**Security posture reports for modern web apps.**

A security scanner for both a **deployed site** (`scan`) and a **source tree**
(`audit`), producing one score, one CI exit code, and JSON / SARIF / HTML
reports.

## Features

- **Web Scan (`scan`)** — passive checks against a live URL:
  - **Headers**: HSTS, Content-Security-Policy (including `unsafe-inline` /
    `unsafe-eval` / wildcard quality), X-Content-Type-Options, Referrer-Policy,
    clickjacking (`X-Frame-Options` or CSP `frame-ancestors`), and
    Cross-Origin-Opener-Policy.
  - **HTTPS**: enforces HTTPS, detects mixed content.
  - **TLS**: certificate expiry and deprecated protocol versions.
  - **DNS**: SPF, DMARC (`p=none` is not treated as protection), and CAA.
  - **Supply chain**: missing Subresource Integrity on third-party scripts and
    stylesheets, outdated JS libraries.
  - **Content**: passively detects PII (emails) and exposed secrets in HTML.
  - **Disclosure**: always fetches `/.well-known/security.txt` (RFC 9116).
  - **Probing**: optionally checks for exposed `.env` / `.git` (`--probe`).

- **Code Audit (`audit`)** — static analysis of a local directory:
  - **Secrets**: hardcoded AWS keys, Google API keys, Slack tokens, private keys.
  - **Dependencies**: vulnerable Python packages (via `pip-audit`, bundled) and
    Node.js packages (via `npm audit`, if installed).
  - **Static analysis**: dangerous Python patterns such as `eval()` / `exec()`.

- **Operational**:
  - **CI gate**: `--fail-on` / `--fail-under` exit non-zero (see below).
  - **Reports**: JSON, SARIF 2.1.0 (GitHub code scanning), and HTML.
  - **History**: scan scores are recorded to a local SQLite database and
    rendered as a trend chart in the HTML report.
  - **Alerts**: results can be posted to a Slack/Discord webhook.

## Installation

```bash
git clone https://github.com/forbiddenlink/aegis-audit.git
cd aegis-audit
pip install -e .
```

## Usage

### Web scan

```bash
# Basic scan
aegis scan --url https://example.com

# Deep scan (with file probing) and an HTML report
aegis scan --url https://example.com --probe --format html

# Scan every page listed in a sitemap (bounded by --max-urls)
aegis scan --sitemap https://example.com/sitemap.xml --max-urls 100

# Fail CI only on findings new since a recorded baseline
aegis scan --url https://example.com --baseline .aegis-baseline.json --fail-on high

# Send an alert to Discord
aegis scan --url https://example.com --webhook "https://discord.com/api/webhooks/..."
```

> Only probe hosts you are authorised to test. `--probe` issues requests for
> paths like `/.env` and `/.git/HEAD`.

### Code audit

```bash
# Audit the current directory
aegis audit .

# Audit a specific folder, choose formats
aegis audit ./src --out ./audit-reports --format json,sarif
```

### Failing a build

Gating is opt-in: with no gate flag, both commands report and exit 0.

```bash
# Fail if anything high or worse is found
aegis audit . --fail-on high

# Fail if the score drops below 80
aegis scan --url https://example.com --fail-under 80
```

Exit codes follow the convention used by semgrep and osv-scanner:

| Code | Meaning |
|------|---------|
| `0`  | Clean, or findings present but below the gate |
| `1`  | Findings tripped the gate |
| `>=2`| Tool or usage error — distinct from "found something" |

That distinction matters in CI: a crashed scan must not look like a clean one.

### Baselining (only fail on new findings)

Pointing the scanner at an existing codebase reports every pre-existing issue at
once, which is too noisy to gate on. A baseline records the current findings so a
later run reports and gates only on what is **new**.

```bash
# Capture the current findings as the accepted baseline
aegis audit . --baseline .aegis-baseline.json --update-baseline

# Later runs: pre-existing findings are suppressed; only new ones can fail CI
aegis audit . --baseline .aegis-baseline.json --fail-on high
```

`--baseline` / `--update-baseline` work on both `scan` and `audit`.

The baseline stores only opaque fingerprints (a hash of each finding's rule,
location, and description) — never the finding text or evidence, so a detected
secret is not copied into a committed file. Fingerprints ignore line numbers, so
inserting unrelated code above a finding does not make it look new.

### Suppressing findings

Real repositories contain fake credentials in test fixtures and docs. Add a
`.aegisignore` in the scan root — one glob per line, relative to that root,
`#` for comments, a trailing `/` to exclude a subtree:

```
tests/
docs/examples/*
uv.lock
```

## Scoring

The score is a **deduction pool**: start at 100 and subtract a fixed penalty per
finding, floored at 0.

| Severity | Penalty |
|----------|---------|
| Critical | 100 (disqualifying) |
| High     | 40 |
| Medium   | 15 |
| Low      | 5 |
| Info     | 0 |

Two properties are deliberate:

- **A critical is disqualifying**, not worth "40 points". An exposed `.git` or a
  live private key means the posture has failed.
- **Findings can only ever lower the score.** Categories that were not checked
  are reported as absent rather than scored 100, so nothing donates free points.

Per-category subscores appear alongside the overall score for triage; they are
not averaged into it.

## Docker

```bash
docker build -t aegis .
docker run --rm aegis scan --url https://example.com
```

## Contributing

```bash
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- [Vision](docs/00-vision.md)
- [Releasing](docs/RELEASING.md)
- [Check catalog](docs/07-check-catalog.md)
- [CLI spec](docs/05-cli-spec.md)
