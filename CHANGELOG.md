# Changelog

## 0.1.3 (2026-10-31)

### Added

- Scans follow local composite actions and reusable workflows, including their inputs, outputs, and exported env vars. Findings use the trigger, checks, and token of the calling workflow.
- A labelled benchmark in `benchmark/cases.yml`, scored by `tools/run_benchmark.py` and checked in CI.
- More attacker-controlled fields: commit author and committer emails, fork repository details, and `workflow_run` fields.
- `github.event['issue']['body']` bracket syntax is now understood.
- Codex: `--dangerously-bypass-approvals-and-sandbox`, `--sandbox danger-full-access`, `safety-strategy: unsafe`, `sandbox: danger-full-access`, and `prompt-file`.
- Gemini CLI: `--approval-mode=yolo`.
- Permission-check steps count as guards when they stop the run or a later `if:` uses their result.
- Every tool signature now goes through the same detection tests.
- New prompt inputs: `input` and `system-prompt-file` for GitHub AI Inference, `prompt_file` for Claude Code, and `false-positive-filtering-instructions` for Claude Code Security Review.
- Continue is detected through `continuedev/continue` actions and `@continuedev/cli`.

### Changed

- A finding reached from several workflows is reported once, at its worst severity, and one prompt reports once however many sources reach it.
- `if:` conditions are read as expressions, so `||` inside a function call or parentheses no longer confuses them.
- A guard in a job listed in `needs:` protects the jobs after it, unless they use `always()`.
- A fork check such as `head.repo.fork == false` counts as a guard.
- Prompt injection is High, not Critical, on workflows that only run on `pull_request` or `repository_dispatch`.
- `AIA009` stays on unless every path has a guard.
- Fields such as `.head.sha` and `.number` picked with `jq` no longer count as untrusted.
- Long `(via ...)` chains are shortened.
- Scans are much faster, mostly thanks to the libyaml parser when PyYAML has it.

### Fixed

- A folder such as `.github/claude/` is no longer mistaken for the `claude` command.
- Removed action names that don't exist on GitHub for Aider, Goose, SWE-agent, Continue, and Codex. Those tools are still detected as commands or through their real actions.

### Tests

- Tests for `pnpm dlx` and `yarn dlx` detection. Thanks to @AhmadAnzar.

## 0.1.2 (2026-10-31)

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
