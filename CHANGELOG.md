# Changelog

## Unreleased

### Added

- Ignore reviewed findings with `# ci-agent-audit: ignore AIA006` comments or a `.ci-agent-audit.yml` file, and see everything with `--no-ignore`.
- `AIA007` now checks GitLab CI scripts. Thanks to @kenzyyshahin.
- Project website with a scanner that runs in your browser.

## 0.1.1 (2026-10-31)

### Added

- `AIA010` follows model output through env vars, `$GITHUB_ENV`, step and job outputs, files, and `actions/github-script`.
- `AIA008` detects more ways to check out PR code, including `refs/pull/`, `merge_commit_sha`, `gh pr checkout`, and `git fetch`.

### Changed

- Fixed label checks count as guards, and guards on every branch of an `if:` count as complete.
- Severity is lower when an agent has no shell, when PR code is in an isolated folder, or when a current `actions/checkout` would refuse fork PR code.
- The `AIA004` advice now applies to every AI tool. Thanks to @kenzyyshahin.

### Fixed

- Negated checks such as `!endsWith(github.actor, '[bot]')` no longer count as spoofable.
- `structured_output` is now treated as model text.
- `--fix` no longer changes branch refs to an older version.

## 0.1.0 (2026-10-30)

First public release.

### Added

- Eleven rules (`AIA001` to `AIA011`) covering prompt injection, dangerous agent flags, spoofable and open access, outdated actions, excess permissions, network egress, unpinned MCP servers, untrusted PR checkouts, agent output reaching commands, and direct pushes to the default branch.
- Taint tracking through `env:`, `$GITHUB_ENV`, step and job outputs, `actions/github-script` outputs, and files named in the prompt.
- Severity that reflects protection already in place, such as read-only tokens, read-only sandboxes, and actor guards.
- Signatures for 12 AI tools, added with one YAML file each.
- GitHub Actions and limited GitLab CI support.
- Text, JSON, SARIF 2.1.0, and GitHub annotation output.
- `--fix` for three common misconfigurations.
- A composite GitHub Action and a pre-commit hook.
