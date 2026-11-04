# Contributing to `ci-agent-audit`

Thank you for helping secure AI-powered CI/CD pipelines! `ci-agent-audit` is intentionally architected so that **adding a new AI GitHub Action or CLI tool signature requires editing just one small YAML file**.

## Add a New AI Tool Signature in 5 Minutes

1. **Create one YAML file** in `src/ci_agent_audit/signatures/<tool-id>.yaml`:

```yaml
id: my-ai-action
name: Example AI PR Agent
vendor: Example Vendor
description: Automated AI code review and PR assistant for GitHub Actions.
action_prefixes:
  - example-org/ai-pr-action
cli_binaries:
  - example-ai
cli_packages:          # Optional: package name when run through npx, bunx, or uvx
  - "@example/ai-cli"
cli_subcommands:       # Optional: the subcommands that start the agent, when the tool has other commands or shares its name
  - run
prompt_inputs:
  - prompt
  - instructions
env_prompt_inputs:     # Optional: settings the agent reads from env vars, so they count even when set in workflow or job `env:`
  - agent.instructions # Matches AGENT__INSTRUCTIONS too
cli_prompt_flags:
  - -p
  - --prompt
dangerous_inputs:
  allow_all_users: "true"
dangerous_arg_patterns:
  - pattern: "--unsafe-auto-exec"
    reason: "Executes shell commands without sandboxing or approval."
min_safe_version: "1.2.0"
advisory_url: "https://github.com/example-org/ai-pr-action/security"
```

2. **Validate your signature file** against the schema:

```bash
pytest
python -m ci_agent_audit.cli validate-signatures
```

`tests/test_signatures.py` picks up your file and tests every prompt input, command, package, and flag, so you don't need to write tests for those. If a test asks you to teach `_sample()` your pattern, say so in your pull request and we'll help.

3. **Open a Pull Request** referencing the AI Action/CLI repository documentation!

### Keep a Signature Accurate

- **Commands:** if the tool has commands that don't start the agent, such as `auth` or `models`, set `cli_subcommands` to the ones that do. Otherwise those commands count as agent runs.
- **Default agent mode:** for tools that start an agent without a subcommand, use `cli_non_agent_subcommands` to exclude their management commands while retaining default launches.
- **Flags:** a pattern is searched across the whole `run:` block. `--auto` on its own also matches `--autostash` and `gh pr merge --auto`, so tie short flags to the command: `"tool\\s+run\\s+.*--auto(?:\\s|$)"`.
- **New names:** when a project moves to another GitHub owner, keep the old name in `action_prefixes` and add the new one. Older workflows keep using the old name.

## Report a Detection Problem

A minimal workflow that gets a wrong result is a great first contribution. Open a **false alarm or missed attack** issue, or add it as a test in `tests/test_adversarial.py`.

## Add a Benchmark Case

`benchmark/cases.yml` holds small labelled repositories that say which rules must fire and which must stay quiet. A new case is a good way to show a bug, and it needs no Python. See how the scanner scores with:

```bash
python tools/run_benchmark.py
```

If the scanner can't catch your case yet, mark it `gap: true`. CI keeps every other case passing.

## Running Development Tests

```bash
python -m pip install -e ".[dev]"
pytest -v
```
