# Changelog

## 0.1.0 (unreleased)

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
