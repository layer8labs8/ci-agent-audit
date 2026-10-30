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

## Running Development Tests

```bash
python -m pip install -e ".[dev]"
pytest -v
```
