# Releasing

AegisAudit publishes to PyPI via **trusted publishing** (OIDC). There is no
long-lived API token stored in the repository.

## One-time setup (per PyPI project)

1. On PyPI, open the project's **Publishing** settings (or the
   pending-publisher form if the project does not exist yet).
2. Add a **GitHub** trusted publisher with:
   - Owner: `forbiddenlink`
   - Repository: `aegis-audit`
   - Workflow: `publish.yml`
   - Environment: leave blank (none configured)

That authorizes the `publish.yml` workflow to mint short-lived tokens at
publish time. No `PYPI_API_TOKEN` secret is needed — if one is set, remove it,
because passing a password to `gh-action-pypi-publish` makes it ignore OIDC.

## Cutting a release

The version is single-sourced from `pyproject.toml`; `tool_version` in reports
and the fetcher User-Agent read it from installed package metadata.

1. Bump `version` in `pyproject.toml`.
2. Commit and tag: `git tag vX.Y.Z && git push --tags`.
3. Create a GitHub Release for that tag. Publishing the release triggers
   `publish.yml`, which builds the wheel/sdist and uploads to PyPI.

## Local sanity check before releasing

```bash
uv build
uvx twine check dist/*
```
