# ci-agent-audit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

> **Status: pre-release.** Not yet published to PyPI or the GitHub Marketplace. Install from source for now.

**A security linter for AI-powered CI/CD pipelines, built to run alongside `actionlint` and `zizmor`.**

`ci-agent-audit` statically analyzes GitHub Actions (`.github/workflows/*.yml`) and GitLab CI (`.gitlab-ci.yml`) pipelines that invoke autonomous coding agents and LLMs (`anthropics/claude-code-action`, `google-github-actions/run-gemini-cli`, `openai/codex-action`, `actions/ai-inference`, `pr-agent`, `openhands`, and MCP runners).

## Why `ci-agent-audit` Exists

Traditional GitHub Actions linters focus on `${{ ... }}` shell template injection inside `run:` blocks. A workflow can instead pass untrusted input through YAML `with:` parameters:

```yaml
- uses: anthropics/claude-code-action@v1
  with:
    prompt: "Triage this issue: ${{ github.event.issue.body }}"
```

Tested against `zizmor` 1.31.1 with `--offline`, this example produces only an `unpinned-uses` finding: nothing about the prompt injection. Yet the AI agent treats the untrusted issue body as instructions (**PromptPwnd** indirect prompt injection), which can let attackers exfiltrate `GITHUB_TOKEN` / `ANTHROPIC_API_KEY` or push malicious code.

`ci-agent-audit` covers this gap with taint tracking across `env:`, `with:`, `$GITHUB_ENV`, `$GITHUB_OUTPUT`, and job outputs, plus agent CLI flag inspection, `[bot]` actor bypass detection, MCP version-pinning checks, and SARIF reporting.

---

## Quick Start

```bash
# Install from a source checkout
pip install .

# Scan all workflows in the current repository
ci-agent-audit scan .github/workflows

# Output GitHub Code Scanning SARIF v2.1.0
ci-agent-audit scan .github/workflows --format sarif --output results.sarif

# Apply safe deterministic fixes (upgrade vulnerable action versions, scope permissions)
ci-agent-audit scan .github/workflows --fix
```

## GitHub Action Usage

Add `ci-agent-audit` to `.github/workflows/ai-security.yml`:

```yaml
name: AI Workflow Security Audit
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  audit-ai-workflows:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: layer8labs8/ci-agent-audit@v1
        with:
          paths: ".github/workflows"
          fail-on: "high"
          sarif-output: "ci-agent-audit.sarif"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: "ci-agent-audit.sarif"
```

## `pre-commit` Hook Usage

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/layer8labs8/ci-agent-audit
    rev: v0.1.0
    hooks:
      - id: ci-agent-audit
```

---

## Built-in Security Rules (`AIA001` – `AIA009`)

| Rule ID | Severity | Name | What It Catches |
| :--- | :--- | :--- | :--- |
| **`AIA001`** | Critical | `promptpwnd-untrusted-input` | Untrusted GitHub/GitLab event fields (`issue.body`, `comment.body`, `toJSON(github.event)`, etc.) flowing directly or via `env:`, `$GITHUB_ENV`, step or job outputs, `actions/github-script` outputs, or files named in the prompt into AI prompt sinks, agent step `env:`, or CLI calls. Reported as High when a read-only sandbox, a cleared token, an `author_association` check, or a reusable-workflow trigger may limit the impact. |
| **`AIA002`** | High | `dangerous-agent-permissions` | Dangerous auto-execution / permission-bypass flags (`--dangerously-skip-permissions`, `--permission-mode bypassPermissions`, `--yolo`, `--full-auto`, `Bash(*)`) in CI. |
| **`AIA003`** | Critical | `spoofable-bot-actor-check` | Spoofable `endsWith(github.actor, '[bot]')` conditions. Wildcard access (`allowed_non_write_users: "*"`, `allowed_bots: "*"`, `allow-users: "*"`) is High, or Medium in a read-only sandbox. |
| **`AIA004`** | High | `vulnerable-ai-action-version` | AI Actions pinned to mutable branches (`@main`), floating tags (`@v1`, reported as Medium), or vulnerable releases (e.g., `anthropics/claude-code-action < v1.0.94`). |
| **`AIA005`** | High | `overprivileged-ai-token` | Missing least-privilege `permissions:` block or `write-all` / `contents: write` / `actions: write` / `packages: write` on issue/PR-triggered AI jobs. |
| **`AIA006`** | Medium | `missing-egress-firewall` | AI agent on a privileged public trigger without outbound network blocking (`step-security/harden-runner` with `egress-policy: block`, a firewall runner, or a read-only sandbox). Fork `pull_request` runs are excluded because they receive no secrets. |
| **`AIA007`** | High | `unpinned-mcp-server-in-ci` | Dynamic execution of unpinned MCP servers (`npx -y @scope/mcp-server` or `uvx`) inside CI pipelines. |
| **`AIA008`** | Critical | `ai-pull-request-target-checkout` | `pull_request_target` workflow checking out untrusted PR head code and executing an AI coding agent with base repository secrets. |
| **`AIA009`** | High | `agent-fetches-untrusted-context` | Agent told or allowed to read issue/PR text through `gh` on a privileged public or scheduled trigger, with no `author_association` gate. |

## Known Limitations

Static analysis finds risky patterns, not proven exploits. A clean report does not mean a workflow is safe.

- Taint is tracked per `run:` block, so an unrelated tainted variable in the same block as an agent call is also reported.
- Data passed through artifacts, caches, or custom scripts is not followed. Files are followed only within a job, and only when the prompt or a later step names them.
- A read-only sandbox is taken from the action's `sandbox:` input as written. Its behavior is not verified.
- Agents that read issue text through their own built-in tools, with no `gh` mention in the workflow, are not detected.
- Reusable workflows and composite actions are not followed into their own files.
- `--fix` replaces `permissions: write-all` with `contents: read`. Add back any scope your agent genuinely needs.

---

## Contributing (1 YAML File = 1 New AI Tool Signature!)

Adding support for a new AI GitHub Action, GitLab CI component, or AI CLI runner requires **only one ~25-line YAML file** inside [`src/ci_agent_audit/signatures/`](src/ci_agent_audit/signatures/).

See [CONTRIBUTING.md](CONTRIBUTING.md) to ship your first pull request in under 5 minutes!
