"""Adversarial regression tests: attacker-style workflows and false-positive traps."""

from __future__ import annotations

from pathlib import Path
import textwrap

import pytest
import yaml

from ci_agent_audit.cli import main
from ci_agent_audit.fixer import apply_fixes_to_file, apply_fixes_to_text
from ci_agent_audit.rules import scan_workflow_file

ISSUES_HEADER = """
name: Adversarial
on:
  issues:
    types: [opened]
permissions:
  contents: read
"""

SAFE_ACTION = "anthropics/claude-code-action@v1.0.100"


def _rule_ids(tmp_path: Path, jobs: str, header: str = ISSUES_HEADER) -> set[str]:
    wf = tmp_path / "wf.yml"
    wf.write_text(header + textwrap.dedent(jobs), encoding="utf-8")
    return {f.rule_id for f in scan_workflow_file(wf)}


def _action_job(*with_lines: str, uses: str = SAFE_ACTION) -> str:
    inputs = "\n".join(f"          {line}" for line in with_lines)
    return f"""
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: {uses}
        with:
{inputs}
"""


@pytest.mark.parametrize(
    "expression",
    [
        "toJSON(github.event)",
        "toJson(github.event.issue)",
        "toJSON(github.event.comment)",
        "github.event.commits.*.message",
        "github.event.client_payload.prompt",
    ],
)
def test_whole_event_objects_are_tainted(tmp_path: Path, expression: str) -> None:
    jobs = _action_job(f'prompt: "Triage ${{{{ {expression} }}}}"')
    assert "AIA001" in _rule_ids(tmp_path, jobs)


@pytest.mark.parametrize(
    "expression",
    ["github.event.issue.number", "github.event.pull_request.number", "github.event.repository.name"],
)
def test_trusted_event_fields_are_not_tainted(tmp_path: Path, expression: str) -> None:
    jobs = _action_job(f'prompt: "Triage ${{{{ {expression} }}}}"')
    assert "AIA001" not in _rule_ids(tmp_path, jobs)


def test_taint_through_step_output(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: grab
            run: echo "body=${{ github.event.issue.body }}" >> "$GITHUB_OUTPUT"
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Triage ${{ steps.grab.outputs.body }}"
    """
    assert "AIA001" in _rule_ids(tmp_path, jobs)


def test_taint_through_github_env(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - run: echo "BODY=${{ github.event.issue.body }}" >> $GITHUB_ENV
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Triage ${{ env.BODY }}"
    """
    assert "AIA001" in _rule_ids(tmp_path, jobs)


def test_taint_through_shell_variable_and_heredoc(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: grab
            run: |
              RAW="${{ github.event.comment.body }}"
              {
                echo "body<<EOF"
                echo "$RAW"
                echo "EOF"
              } >> "$GITHUB_OUTPUT"
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "${{ steps.grab.outputs.body }}"
    """
    assert "AIA001" in _rule_ids(tmp_path, jobs)


def test_taint_through_gh_cli_output(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: grab
            run: echo "body=$(gh issue view 1 --json body)" >> "$GITHUB_OUTPUT"
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "${{ steps.grab.outputs.body }}"
    """
    assert "AIA001" in _rule_ids(tmp_path, jobs)


def test_taint_through_job_outputs_across_needs(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        needs: prepare
        runs-on: ubuntu-latest
        steps:
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "${{ needs.prepare.outputs.body }}"
      prepare:
        runs-on: ubuntu-latest
        outputs:
          body: ${{ steps.grab.outputs.body }}
        steps:
          - id: grab
            run: echo "body=${{ github.event.issue.body }}" >> "$GITHUB_OUTPUT"
    """
    assert "AIA001" in _rule_ids(tmp_path, jobs)


def test_clean_step_output_is_not_tainted(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: grab
            run: echo "sha=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Review ${{ steps.grab.outputs.sha }}"
    """
    assert "AIA001" not in _rule_ids(tmp_path, jobs)


def test_agent_told_to_fetch_issue_with_gh(tmp_path: Path) -> None:
    jobs = _action_job(
        'prompt: "Read issue ${{ github.event.issue.number }} with gh issue view and fix it"',
        'claude_args: "--allowedTools Bash(gh:*)"',
    )
    assert "AIA009" in _rule_ids(tmp_path, jobs)


def test_gh_tool_grant_alone_triggers_indirect_rule(tmp_path: Path) -> None:
    jobs = _action_job('prompt: "Triage"', 'claude_args: "--allowedTools Bash(gh:*)"')
    assert "AIA009" in _rule_ids(tmp_path, jobs)


def test_indirect_rule_respects_author_association_guard(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        if: github.event.issue.author_association == 'OWNER'
        runs-on: ubuntu-latest
        steps:
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Run gh issue view and fix it"
    """
    assert "AIA009" not in _rule_ids(tmp_path, jobs)


def test_indirect_rule_ignores_trusted_triggers(tmp_path: Path) -> None:
    header = "on: [push]\npermissions:\n  contents: read\n"
    jobs = _action_job('prompt: "Run gh issue view and summarize"')
    assert "AIA009" not in _rule_ids(tmp_path, jobs, header)


def _findings(tmp_path: Path, jobs: str, header: str = ISSUES_HEADER) -> list:
    wf = tmp_path / "wf.yml"
    wf.write_text(header + textwrap.dedent(jobs), encoding="utf-8")
    return scan_workflow_file(wf)


def test_issue_written_to_file_then_named_in_prompt(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - run: |
              ISSUE_FILE=current-issue.json
              gh issue view "$N" \\
                --json title,body \\
                > "$ISSUE_FILE"
          - uses: openai/codex-action@v1.7.0
            with:
              prompt: "Read current-issue.json and find duplicates"
    """
    assert "AIA001" in _rule_ids(tmp_path, jobs)


def test_event_payload_written_to_file_then_named_in_prompt(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - run: jq '.issue | {title, body}' "$GITHUB_EVENT_PATH" > issue.json
          - uses: openai/codex-action@v1.7.0
            with:
              prompt: "Translate issue.json"
    """
    assert "AIA001" in _rule_ids(tmp_path, jobs)


def test_gh_fetch_of_numbers_only_is_not_tainted(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: find
            run: |
              IDS="$(gh issue list --json number)"
              echo "ids=${IDS}" >> "${GITHUB_OUTPUT}"
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Check ${{ steps.find.outputs.ids }}"
    """
    assert "AIA001" not in _rule_ids(tmp_path, jobs)


def test_tainted_env_on_agent_step_is_a_sink(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - uses: google-github-actions/run-gemini-cli@v0.1.20
            env:
              ISSUE_BODY: ${{ github.event.issue.body }}
            with:
              prompt: /gemini-triage
    """
    assert "AIA001" in _rule_ids(tmp_path, jobs)


def test_scheduled_issue_list_reaches_agent_env(tmp_path: Path) -> None:
    header = "on:\n  schedule:\n    - cron: '0 * * * *'\npermissions:\n  contents: read\n"
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: find
            run: |
              ISSUES="$(gh issue list \\
                --json number,title,body)"
              echo "issues=${ISSUES}" >> "${GITHUB_OUTPUT}"
          - uses: google-github-actions/run-gemini-cli@v0.1.20
            env:
              ISSUES_TO_TRIAGE: ${{ steps.find.outputs.issues }}
            with:
              prompt: /triage
    """
    assert "AIA001" in _rule_ids(tmp_path, jobs, header)


def test_github_script_output_is_tainted(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: data
            uses: actions/github-script@v7
            with:
              script: |
                const { data: issue } = await github.rest.issues.get(context.issue);
                core.setOutput('number', issue.number);
                core.setOutput('body', issue.body);
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Triage ${{ steps.data.outputs.body }}"
    """
    assert "AIA001" in _rule_ids(tmp_path, jobs)


def test_scheduled_agent_with_gh_tools_is_flagged(tmp_path: Path) -> None:
    header = "on:\n  schedule:\n    - cron: '0 0 * * *'\npermissions:\n  contents: read\n"
    jobs = _action_job(
        "prompt: /report",
        'settings: \'{"tools": ["run_shell_command(gh search issues)"]}\'',
        uses="google-github-actions/run-gemini-cli@v0.1.20",
    )
    assert "AIA009" in _rule_ids(tmp_path, jobs, header)


def test_sub_action_that_runs_no_agent_is_ignored(tmp_path: Path) -> None:
    jobs = _action_job(
        "required_approvals: 2", uses="anthropics/claude-code-action/agent-approval-check@main"
    )
    assert _rule_ids(tmp_path, jobs) == set()


def test_permission_mode_auto_is_not_a_bypass(tmp_path: Path) -> None:
    jobs = _action_job('prompt: "hi"', 'claude_args: "--permission-mode auto"')
    assert "AIA002" not in _rule_ids(tmp_path, jobs)


def test_fork_pull_request_has_no_egress_finding(tmp_path: Path) -> None:
    header = "on: [pull_request]\npermissions:\n  contents: read\n"
    assert "AIA006" not in _rule_ids(tmp_path, _action_job('prompt: "Review"'), header)


def test_read_only_sandbox_lowers_severity_and_clears_egress(tmp_path: Path) -> None:
    jobs = _action_job(
        'allow-users: "*"',
        "sandbox: read-only",
        'prompt: "Label ${{ github.event.issue.body }}"',
        uses="openai/codex-action@v1.7.0",
    )
    by_rule = {f.rule_id: f.severity.value for f in _findings(tmp_path, jobs)}
    assert by_rule["AIA001"] == "high"
    assert by_rule["AIA003"] == "medium"
    assert "AIA006" not in by_rule


def test_wildcard_access_without_sandbox_is_high(tmp_path: Path) -> None:
    jobs = _action_job('allowed_non_write_users: "*"', 'prompt: "hi"')
    assert {f.rule_id: f.severity.value for f in _findings(tmp_path, jobs)}["AIA003"] == "high"


def test_spoofable_bot_check_stays_critical(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        if: endsWith(github.actor, '[bot]')
        runs-on: ubuntu-latest
        steps:
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "hi"
    """
    assert {f.rule_id: f.severity.value for f in _findings(tmp_path, jobs)}["AIA003"] == "critical"


def test_floating_tag_is_medium(tmp_path: Path) -> None:
    jobs = _action_job('prompt: "hi"', uses="anthropics/claude-code-action@v1")
    assert {f.rule_id: f.severity.value for f in _findings(tmp_path, jobs)}["AIA004"] == "medium"


def test_agent_step_with_cleared_token_skips_permissions_finding(tmp_path: Path) -> None:
    header = "on: [issues]\npermissions:\n  actions: write\n"
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - uses: google-github-actions/run-gemini-cli@v0.1.20
            env:
              GITHUB_TOKEN: ''
            with:
              prompt: /triage
    """
    assert "AIA005" not in _rule_ids(tmp_path, jobs, header)


def test_boolean_check_of_event_object_is_not_tainted(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - uses: google-github-actions/run-gemini-cli@v0.1.20
            env:
              IS_PR: ${{ !!github.event.pull_request }}
            with:
              prompt: /triage
    """
    assert "AIA001" not in _rule_ids(tmp_path, jobs)


def test_issue_fields_are_empty_on_schedule(tmp_path: Path) -> None:
    header = "on:\n  schedule:\n    - cron: '0 * * * *'\n  workflow_dispatch:\npermissions:\n  contents: read\n"
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - uses: google-github-actions/run-gemini-cli@v0.1.20
            env:
              ISSUE_BODY: ${{ github.event.issue.body }}
            with:
              prompt: /refresh
    """
    assert "AIA001" not in _rule_ids(tmp_path, jobs, header)


def test_jq_comparison_is_not_a_file_write(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - run: gh issue list --json title,body | jq '[.[] | select((.labels | length) > 1)]'
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Pick 1 issue"
    """
    assert "AIA001" not in _rule_ids(tmp_path, jobs)


@pytest.mark.parametrize(
    "header, token",
    [
        (ISSUES_HEADER, "''"),
        ("on: [workflow_call]\npermissions:\n  contents: read\n", "${{ secrets.GITHUB_TOKEN }}"),
    ],
)
def test_mitigated_or_gated_elsewhere_taint_is_high(tmp_path: Path, header: str, token: str) -> None:
    jobs = f"""
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@v0.1.20
        env:
          GITHUB_TOKEN: {token}
          ISSUE_BODY: ${{{{ github.event.issue.body }}}}
        with:
          prompt: /triage
"""
    severities = {f.severity.value for f in _findings(tmp_path, jobs, header) if f.rule_id == "AIA001"}
    assert severities == {"high"}


def test_indirect_rule_covers_workflow_run(tmp_path: Path) -> None:
    header = "on:\n  workflow_run:\n    workflows: [CI]\npermissions:\n  contents: read\n"
    jobs = _action_job('prompt: "Fix CI"', 'claude_args: "--allowedTools Bash(gh:*)"')
    assert "AIA009" in _rule_ids(tmp_path, jobs, header)


def test_codex_allow_users_wildcard_is_flagged(tmp_path: Path) -> None:
    jobs = _action_job('allow-users: "*"', 'prompt: "hi"', uses="openai/codex-action@v1.7.0")
    assert "AIA003" in _rule_ids(tmp_path, jobs)


def test_allowed_bots_wildcard_is_flagged(tmp_path: Path) -> None:
    jobs = _action_job('allowed_bots: "*"', 'prompt: "hi"')
    assert "AIA003" in _rule_ids(tmp_path, jobs)


@pytest.mark.parametrize("ref", ["v1", "v1.0"])
def test_floating_tags_are_flagged(tmp_path: Path, ref: str) -> None:
    jobs = _action_job('prompt: "hi"', uses=f"anthropics/claude-code-action@{ref}")
    assert "AIA004" in _rule_ids(tmp_path, jobs)


def test_sha_pin_is_not_flagged(tmp_path: Path) -> None:
    sha = "a" * 40
    jobs = _action_job('prompt: "hi"', uses=f"anthropics/claude-code-action@{sha}")
    assert "AIA004" not in _rule_ids(tmp_path, jobs)


@pytest.mark.parametrize(
    "command",
    [
        'timeout 60 claude -p "$BODY" --dangerously-skip-permissions',
        'sudo claude -p "$BODY" --dangerously-skip-permissions',
        'CI=1 claude -p "$BODY" --dangerously-skip-permissions',
        'env CI=1 claude -p "$BODY" --dangerously-skip-permissions',
        './node_modules/.bin/claude -p "$BODY" --dangerously-skip-permissions',
        'npx -y @anthropic-ai/claude-code -p "$BODY" --dangerously-skip-permissions',
        'npx @anthropic-ai/claude-code@latest -p "$BODY" --dangerously-skip-permissions',
        'bunx @anthropic-ai/claude-code -p "$BODY" --dangerously-skip-permissions',
        'OUT=$(claude -p "$BODY" --dangerously-skip-permissions)',
    ],
)
def test_wrapped_cli_invocations_are_detected(tmp_path: Path, command: str) -> None:
    jobs = f"""
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - env:
          BODY: ${{{{ github.event.issue.body }}}}
        run: {command}
"""
    assert {"AIA001", "AIA002"} <= _rule_ids(tmp_path, jobs)


@pytest.mark.parametrize(
    "command",
    [
        "claude --version",
        "echo hi",
        "claude-sync push",
        "goose up",
        "goose -dir migrations postgres up",
    ],
)
def test_non_agent_commands_are_not_ai_steps(tmp_path: Path, command: str) -> None:
    jobs = f"""
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: {command}
"""
    assert _rule_ids(tmp_path, jobs) == set()


def test_goose_agent_run_is_detected(tmp_path: Path) -> None:
    jobs = """
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - env:
          BODY: ${{ github.event.issue.body }}
        run: goose run -t "$BODY"
"""
    assert "AIA001" in _rule_ids(tmp_path, jobs)


def test_egress_rule_is_silent_on_trusted_triggers(tmp_path: Path) -> None:
    header = "on: [push]\npermissions:\n  contents: read\n"
    assert "AIA006" not in _rule_ids(tmp_path, _action_job('prompt: "Review"'), header)


def test_harden_runner_audit_mode_is_not_a_firewall(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - uses: step-security/harden-runner@v2
            with:
              egress-policy: audit
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Review"
    """
    assert "AIA006" in _rule_ids(tmp_path, jobs)


@pytest.mark.parametrize(
    "scope, source, reader",
    [
        (
            "workflow",
            "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: x\n    steps: []\n",
            lambda d: d["permissions"],
        ),
        (
            "job",
            "on: push\njobs:\n  a:\n    runs-on: x\n    permissions: write-all\n    steps: []\n",
            lambda d: d["jobs"]["a"]["permissions"],
        ),
    ],
)
def test_fixer_keeps_yaml_valid_at_any_indent(scope: str, source: str, reader) -> None:
    fixed, notes = apply_fixes_to_text(source)
    assert notes
    assert reader(yaml.safe_load(fixed)) == {"contents": "read"}, scope


def test_fixer_refuses_to_emit_invalid_yaml() -> None:
    source = "on: push\njobs: [\n  permissions: write-all\n"
    fixed, notes = apply_fixes_to_text(source)
    assert fixed == source
    assert notes == []


def test_fixer_preserves_line_endings(tmp_path: Path) -> None:
    wf = tmp_path / "wf.yml"
    wf.write_bytes(b"on: push\r\npermissions: write-all\r\njobs: {}\r\n")
    modified, _ = apply_fixes_to_file(wf)
    data = wf.read_bytes()
    assert modified
    assert data.count(b"\r\n") == data.count(b"\n")
    assert yaml.safe_load(data)["permissions"] == {"contents": "read"}


def test_invalid_yaml_is_reported_not_crashed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text("jobs: [\n", encoding="utf-8")
    assert main(["scan", str(bad)]) == 2
    assert "bad.yml" in capsys.readouterr().err


def test_empty_scan_warns_instead_of_passing_silently(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", str(tmp_path)]) == 2
    assert "No workflow files" in capsys.readouterr().err
