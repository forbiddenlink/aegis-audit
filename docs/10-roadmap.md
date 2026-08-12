# Roadmap

Phase 1 (MVP):

- CLI + config + allowlist enforcement
- fetcher + 6-8 checks (Headers, SSL, security.txt)
- JSON + HTML report
- tests for checks

Phase 2 (Product polish):

- SARIF report output (for CI integrations)
- scoring rubric + category scores
- baseline comparison (diff vs last scan) — shipped (`--baseline`)
- SQLite scan history (optional)

Phase 3 (Portfolio flex):

- GitHub Action integration (PR comment + failing thresholds)
- “Fix guidance” snippets per framework (Next.js, Nginx, ASP.NET)

Phase 4 (Nice-to-have):

- PDF output
- dashboard viewer for reports
