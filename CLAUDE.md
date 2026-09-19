# aegis-audit (AegisAudit)

Security posture CLI (`aegis`) with two subcommands: `scan` (passive checks against a
deployed URL) and `audit` (static analysis of a local source tree). Both produce one
score, one CI exit code, and JSON / SARIF 2.1.0 / HTML reports. Repo:
github.com/forbiddenlink/aegis-audit.

## Stack

- Python >=3.11, packaged with hatchling
- CLI: Typer + Rich; validation: Pydantic v2; HTTP: httpx; templating: Jinja2
- `uv` for dependency management (`uv.lock` present)
- Lint: Ruff (rule set pinned to `E4,E7,E9,F` deliberately, see Gotchas); types: mypy
  `strict = true`; tests: pytest + pytest-asyncio + pytest-cov

## Commands

```bash
uv sync                       # or: pip install -e ".[dev]"
uv run aegis scan --url https://example.com
uv run aegis audit .
make check                    # mypy aegisaudit && pytest
make test                     # pytest
make typecheck                # mypy aegisaudit
make security                 # pip-audit (also: make audit, same command)
make lint-baseline             # ruff check .
```

Docker: `docker build -t aegis . && docker run --rm aegis scan --url https://example.com`

## Layout

- `aegisaudit/cli.py` - Typer app entry point (`aegis` console script)
- `aegisaudit/checks/` - web-scan checks: `headers.py`, `https.py`, `tls.py`, `dns.py`,
  `cookies.py`, `sri.py`, `security_txt.py`, `javascript.py`, `exposure.py`, `secrets.py`
- `aegisaudit/sast/` - source-tree audit: `scanner.py`, `static.py`, `secrets.py`,
  `dependencies.py` (pip-audit + optional npm audit), `ignore.py` (`.aegisignore`
  handling)
- `aegisaudit/reporters/` - `json_report.py`, `sarif_report.py`, `html_report.py`,
  `summary_report.py`
- `aegisaudit/integrations/notion.py` - posts results to a Notion page
- `aegisaudit/{baseline,scoring,gating,history,policy,fetcher,sitemap,ssrf,config,models,
  runner,notifications}.py` - baseline fingerprinting, deduction-pool scoring, `--fail-on`
  /`--fail-under` gating, SQLite scan history, SSRF-safe fetching, sitemap crawling
- `tests/` - one test file per module, `tests/test_sarif.py` validates output against
  the official SARIF 2.1.0 schema
- `docs/` - numbered design docs (vision, architecture, data model, CLI spec, check
  catalog, roadmap); `docs/RELEASING.md` for the release process

## Scoring model

Deduction pool starting at 100: Critical is disqualifying (-100), High -40, Medium -15,
Low -5, Info -0. A category that was not checked is reported as absent, never scored
100 - findings can only ever lower the score. Per-category subscores are for triage
and are not averaged into the overall score.

## Config

No environment variables are read; the Notion token and Slack/Discord webhook URL are
passed as CLI flags, not env vars. `.aegisignore` (glob-per-line, `#` comments, trailing
`/` for a subtree) suppresses findings in a scan root, same syntax as `.gitignore`.

## Gotchas

- Ruff's rule selection is pinned explicitly to `E4,E7,E9,F` in `pyproject.toml`
  (`tool.ruff.lint.select`) because Ruff's own "default" rule set grew across versions
  and would otherwise flag hundreds of pre-existing findings on a routine dependency
  bump. Widen it only via a deliberate, reviewed edit.
- Dependency upper bounds are intentional (see comments in `pyproject.toml`): they stop
  `uv lock --upgrade` from silently crossing a major version. Dependabot's grouped PRs
  are the sanctioned upgrade path.
- Baseline fingerprints (`--baseline`/`--update-baseline`) hash rule + location +
  description only, never the finding text, and ignore line numbers so inserting
  unrelated code above a finding does not make it look new.
- Gating is opt-in: with no `--fail-on`/`--fail-under` flag, both `scan` and `audit`
  report and exit 0. Exit code `>=2` means a tool/usage error, distinct from "findings
  tripped the gate" (`1`).
