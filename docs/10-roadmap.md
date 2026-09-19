# Roadmap

Phase 1 (MVP) - shipped:

- CLI + config + allowlist enforcement (`ssrf.py`)
- fetcher + checks (headers, HTTPS, TLS, DNS, cookies, SRI, security.txt,
  JavaScript, exposure probing, secrets)
- JSON + HTML report
- tests for checks
- also shipped, beyond original MVP scope: the `aegis audit` static-analysis
  subcommand (`aegisaudit/sast/`)

Phase 2 (Product polish) - shipped:

- SARIF 2.1.0 report output (for CI integrations, GitHub code scanning)
- scoring rubric + category scores (deduction-pool model, see CLAUDE.md)
- baseline comparison (diff vs last scan, `--baseline`/`--update-baseline`)
- SQLite scan history (`history.py`)
- CI gating (`--fail-on`/`--fail-under`)

Phase 3 (Portfolio flex) - not started:

- GitHub Action integration (PR comment + failing thresholds); SARIF upload
  to GitHub code scanning works today via `--format sarif`, but there is no
  published composite Action
- "Fix guidance" snippets per framework (Next.js, Nginx, ASP.NET)

Phase 4 (Nice-to-have) - not started:

- PDF output
- dashboard viewer for reports
