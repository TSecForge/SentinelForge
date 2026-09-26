# Releasing

1. Update `__version__` in `src/sentinelforge/__init__.py`, the `sentinelforge-detect==` pin and `version` in
   `backend/pyproject.toml`, and add a section to `CHANGELOG.md`.
2. Commit, then tag and push:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```
3. `.github/workflows/release.yml` checks that the tag matches the version, builds the wheel and sdist, and creates a
   GitHub release with the CHANGELOG section as notes and the packages attached.

## PyPI (one-time setup)

Publishing uses [trusted publishing](https://docs.pypi.org/trusted-publishers/), so no PyPI token is stored anywhere:

1. On pypi.org → *Your projects* → *Publishing* → **Add a pending publisher**:
   - PyPI project name: `sentinelforge-detect`
   - Owner: `TSecForge`, repository: `SentinelForge`
   - Workflow: `release.yml`, environment: `pypi`
2. In the GitHub repo: *Settings → Environments* → create `pypi`. Optionally add yourself as a required reviewer.
3. *Settings → Secrets and variables → Actions → Variables* → add `PYPI_PUBLISH` = `true`.

The next tag then publishes to PyPI. To publish a tag that was already released, re-run the workflow for it.

## GitHub Marketplace (optional)

`action.yml` sits at the repository root, so the Action already works as `uses: TSecForge/SentinelForge@v0.2.0`.
To list it in the Marketplace, edit the GitHub release and tick **Publish this Action to the GitHub Marketplace**.
