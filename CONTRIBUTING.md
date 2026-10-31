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
cli_subcommands:       # Optional: required subcommands, for binary names shared with other tools
  - run
prompt_inputs:
  - prompt
  - instructions
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

3. **Open a Pull Request** referencing the AI Action/CLI repository documentation!

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
