.PHONY: check test typecheck security audit lint-baseline

check:
	uv run mypy aegisaudit
	uv run pytest

test:
	uv run pytest

typecheck:
	uv run mypy aegisaudit

security:
	uv run pip-audit

audit:
	uv run pip-audit

lint-baseline:
	uv run ruff check .
