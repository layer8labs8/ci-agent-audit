# Releasing

Maintainers follow these steps to publish a new version.

## One-time setup

1. On PyPI, add a pending trusted publisher with these values:
   - Project name: `ci-agent-audit`
   - Owner: `layer8labs8`
   - Repository: `ci-agent-audit`
   - Workflow: `release.yml`
   - Environment: `pypi`
2. On GitHub, create an environment named `pypi` and add yourself as a required reviewer.
3. In the repository's security settings, turn on private vulnerability reporting.

## Each release

1. Update `__version__` in `src/ci_agent_audit/__init__.py` and `version` in `pyproject.toml`.
2. Replace `unreleased` in `CHANGELOG.md` with the release date.
3. Merge to `main` and confirm that CI passes.
4. Create and push the tag:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

5. Approve the `pypi` deployment on the workflow run. The workflow then publishes to PyPI and creates the GitHub release.

A release can't be replaced on PyPI, so a mistake needs a new version number.
