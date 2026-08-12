# AegisAudit — Vision

Goal: Help me (and later others) harden websites I build by auditing security posture and producing actionable reports.
This is a learning tool and a real guardrail for my own projects.

Principles:

- Safe-by-design: no exploit attempts, no payload injection, no auth bypass testing.
- Clear scope: only scan domains I control or have explicit permission to assess.
- Actionable output: every finding includes evidence + remediation + references.

Success looks like:

- I can run `aegis scan` against my staging/prod and get a clear report in < 60 seconds for a small site.
- Reports help me fix real issues (headers, cookies, CSP quality, HTTPS enforcement).
- Optional CI mode prevents regressions via score/severity gating (`--fail-on`,
  `--fail-under`), with baseline diffing (`--baseline`) to fail only on findings
  new since a recorded baseline.
