# CLI Spec

Command:

```
aegis scan [OPTIONS]
aegis audit DIRECTORY [OPTIONS]
```

Shared options:

- `--out DIR`              Output directory (`./aegis-report` for scan, `./aegis-audit` for audit)
- `--format`               `json`, `html`, `sarif`, `summary`, `all` (repeatable or comma-separated)
- `--fail-on SEVERITY`     Exit 1 if any finding is at or above this severity
- `--fail-under SCORE`     Exit 1 if the overall score is below this value (0–100)
- `--baseline PATH`        Report/gate only on findings new since this baseline
- `--update-baseline`      Write current findings to `--baseline` and exit 0

`scan` options:

- `--url URL`              Repeatable target URL
- `--file PATH`            Newline-delimited URL list
- `--sitemap URL`          Sitemap to expand (bounded by `--max-urls`)
- `--max-urls INT`         Cap on sitemap expansion (default 200)
- `--config PATH`          YAML config (`aegis.yml`)
- `--probe`                Also request `/.env` and `/.git/HEAD`
- `--webhook URL`          Slack or Discord webhook (allowlisted hosts only)

`scan` always fetches `/.well-known/security.txt` for each origin (RFC 9116).
That is a public disclosure file, not an exposure probe.

Exit codes follow semgrep / osv-scanner:

- `0` success (clean, or findings present but below the gate)
- `1` findings tripped `--fail-on` / `--fail-under`
- `>=2` usage or tool error (distinct from "found something")
