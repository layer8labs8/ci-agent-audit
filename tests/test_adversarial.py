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


def _severity(tmp_path: Path, jobs: str, rule_id: str, header: str = ISSUES_HEADER) -> str:
    return {f.rule_id: f.severity.value for f in _findings(tmp_path, jobs, header)}[rule_id]


def test_model_output_in_run_block_is_critical(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: ai
            uses: actions/ai-inference@v1
            with:
              prompt: "Label this"
          - run: echo "${{ steps.ai.outputs.response }}"
    """
    assert _severity(tmp_path, jobs, "AIA010") == "critical"


def test_model_output_passed_as_data_is_not_flagged(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: ai
            uses: actions/ai-inference@v1
            with:
              prompt: "Label this"
          - env:
              ANSWER: ${{ steps.ai.outputs.response }}
            run: printf '%s' "$ANSWER" > answer.txt
    """
    assert "AIA010" not in _rule_ids(tmp_path, jobs)


def test_model_chosen_checkout_ref_is_high(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: ai
            uses: actions/ai-inference@v1
            with:
              prompt: "Which branch?"
          - uses: actions/checkout@v4
            with:
              ref: ${{ steps.ai.outputs.response }}
    """
    assert _severity(tmp_path, jobs, "AIA010") == "high"


def test_model_output_env_used_by_git_is_high(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: ai
            uses: actions/ai-inference@v1
            with:
              prompt: "Which branch?"
          - env:
              TARGET: ${{ steps.ai.outputs.response }}
            run: git checkout -b "$TARGET"
    """
    assert _severity(tmp_path, jobs, "AIA010") == "high"


def test_model_output_env_in_eval_is_critical(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: ai
            uses: actions/ai-inference@v1
            with:
              prompt: "Which command?"
          - env:
              CMD: ${{ steps.ai.outputs.response }}
            run: eval "$CMD"
    """
    assert _severity(tmp_path, jobs, "AIA010") == "critical"


def test_agent_metadata_outputs_are_not_model_text(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: claude
            uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Review"
          - run: cat "${{ steps.claude.outputs.execution_file }}"
    """
    assert "AIA010" not in _rule_ids(tmp_path, jobs)


def test_model_output_rule_ignores_trusted_triggers(tmp_path: Path) -> None:
    header = "on: [push]\npermissions:\n  contents: read\n"
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: ai
            uses: actions/ai-inference@v1
            with:
              prompt: "Summarize"
          - run: echo "${{ steps.ai.outputs.response }}"
    """
    assert "AIA010" not in _rule_ids(tmp_path, jobs, header)


@pytest.mark.parametrize(
    "command",
    ["git push origin main", "git push origin HEAD:master", "git push origin HEAD:refs/heads/main"],
)
def test_agent_pushing_to_default_branch_is_flagged(tmp_path: Path, command: str) -> None:
    jobs = f"""
jobs:
  docs:
    runs-on: ubuntu-latest
    steps:
      - run: claude -p "Update the changelog"
      - run: |
          git commit -am "docs: update"
          {command}
"""
    assert "AIA011" in _rule_ids(tmp_path, jobs)


@pytest.mark.parametrize("command", ["git push origin docs-bot/changelog", "git push origin main --dry-run"])
def test_review_branch_push_is_not_flagged(tmp_path: Path, command: str) -> None:
    jobs = f"""
jobs:
  docs:
    runs-on: ubuntu-latest
    steps:
      - run: claude -p "Update the changelog"
      - run: {command}
"""
    assert "AIA011" not in _rule_ids(tmp_path, jobs)


def test_push_before_agent_runs_is_not_flagged(tmp_path: Path) -> None:
    jobs = """
    jobs:
      docs:
        runs-on: ubuntu-latest
        steps:
          - run: git push origin main
          - run: claude -p "Update the changelog"
    """
    assert "AIA011" not in _rule_ids(tmp_path, jobs)


@pytest.mark.parametrize(
    "guard",
    [
        "github.event.comment.author_association == 'OWNER'",
        "github.actor == 'trusted-bot'",
        "contains(fromJSON('[\"alice\", \"bob\"]'), github.actor)",
        "github.event.pull_request.head.repo.full_name == github.repository",
    ],
)
def test_complete_guard_lowers_taint_to_medium(tmp_path: Path, guard: str) -> None:
    jobs = f"""
jobs:
  ai:
    if: {guard}
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1.0.100
        with:
          prompt: "Summarise ${{{{ github.event.issue.body }}}}"
"""
    findings = {f.rule_id: f.severity.value for f in _findings(tmp_path, jobs)}
    assert findings["AIA001"] == "medium"
    assert "AIA006" not in findings


def test_step_guard_counts_too(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - if: github.actor == 'trusted-bot'
            uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Summarise ${{ github.event.issue.body }}"
    """
    assert _severity(tmp_path, jobs, "AIA001") == "medium"


def test_guard_covering_one_event_only_stays_high(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        if: github.event_name == 'issues' || github.event.comment.author_association == 'OWNER'
        runs-on: ubuntu-latest
        steps:
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Summarise ${{ github.event.issue.body }}"
    """
    assert _severity(tmp_path, jobs, "AIA001") == "high"


@pytest.mark.parametrize("guard", ["github.actor != 'dependabot[bot]'", "github.event.action == 'opened'"])
def test_non_guards_do_not_lower_severity(tmp_path: Path, guard: str) -> None:
    header = "on:\n  issues:\n    types: [opened]\npermissions: write-all\n"
    jobs = f"""
jobs:
  ai:
    if: {guard}
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1.0.100
        with:
          prompt: "Summarise ${{{{ github.event.issue.body }}}}"
"""
    assert _severity(tmp_path, jobs, "AIA001", header) == "critical"


def test_spoofable_bot_suffix_is_not_a_guard(tmp_path: Path) -> None:
    header = "on:\n  issues:\n    types: [opened]\npermissions: write-all\n"
    jobs = """
    jobs:
      ai:
        if: endsWith(github.actor, '[bot]')
        runs-on: ubuntu-latest
        steps:
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Summarise ${{ github.event.issue.body }}"
    """
    assert _severity(tmp_path, jobs, "AIA001", header) == "critical"


def test_read_only_token_lowers_cli_taint_to_high(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - env:
              BODY: ${{ github.event.issue.body }}
            run: claude -p "$BODY"
    """
    assert _severity(tmp_path, jobs, "AIA001") == "high"


def test_structured_output_is_model_text(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: analyze
            uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Analyze"
          - run: |
              cat <<'EOF' > /tmp/output.json
              ${{ steps.analyze.outputs.structured_output }}
              EOF
    """
    assert _severity(tmp_path, jobs, "AIA010") == "critical"


def test_model_output_relayed_by_a_step_stays_tracked(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: analyze
            uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Analyze"
          - id: parse
            env:
              RESULT: ${{ steps.analyze.outputs.structured_output }}
            run: echo "reason=$(jq -r .reason <<< "$RESULT")" >> "$GITHUB_OUTPUT"
          - run: gh pr comment 1 --body "${{ steps.parse.outputs.reason }}"
    """
    assert _severity(tmp_path, jobs, "AIA010") == "critical"


def test_unrelated_step_output_is_not_model_text(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: analyze
            uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Analyze"
          - id: meta
            run: echo "sha=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"
          - run: echo "${{ steps.meta.outputs.sha }}"
    """
    assert "AIA010" not in _rule_ids(tmp_path, jobs)


def test_fixed_label_gate_is_a_guard(tmp_path: Path) -> None:
    header = "on:\n  issues:\n    types: [labeled]\npermissions: write-all\n"
    jobs = """
    jobs:
      ai:
        if: github.event.label.name == 'agent:pr'
        runs-on: ubuntu-latest
        steps:
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Fix ${{ github.event.issue.body }}"
    """
    findings = {f.rule_id: f.severity.value for f in _findings(tmp_path, jobs, header)}
    assert findings["AIA001"] == "medium"
    assert "AIA005" not in findings
    assert "AIA006" not in findings


def test_any_label_trigger_without_gate_is_not_a_guard(tmp_path: Path) -> None:
    header = "on:\n  issues:\n    types: [opened, labeled]\npermissions: write-all\n"
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Fix ${{ github.event.issue.body }}"
    """
    assert _severity(tmp_path, jobs, "AIA001", header) == "critical"


def _pr_target_job(checkout: str, extra: str = "") -> str:
    return f"""
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: {checkout}
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}{extra}
      - uses: anthropics/claude-code-action@v1.0.100
        with:
          prompt: "Review"
"""


PR_TARGET_HEADER = "on: [pull_request_target]\npermissions:\n  contents: read\n"


def test_floating_checkout_that_refuses_forks_is_high(tmp_path: Path) -> None:
    jobs = _pr_target_job("actions/checkout@v4")
    assert _severity(tmp_path, jobs, "AIA008", PR_TARGET_HEADER) == "high"


def test_unsafe_checkout_opt_in_is_critical(tmp_path: Path) -> None:
    jobs = _pr_target_job("actions/checkout@v4", "\n          allow-unsafe-pr-checkout: true")
    assert _severity(tmp_path, jobs, "AIA008", PR_TARGET_HEADER) == "critical"


def test_sha_pinned_checkout_stays_critical(tmp_path: Path) -> None:
    jobs = _pr_target_job("actions/checkout@" + "a" * 40)
    assert _severity(tmp_path, jobs, "AIA008", PR_TARGET_HEADER) == "critical"


AGENT_STEP = """
      - id: ai
        uses: actions/ai-inference@v1
        with:
          prompt: "Answer"
"""


def _steps(body: str) -> str:
    return "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:" + AGENT_STEP + body


@pytest.mark.parametrize(
    "body",
    [
        "      - uses: actions/github-script@v7\n        with:\n          script: ${{ steps.ai.outputs.response }}\n",
        '      - run: echo "${{ fromJSON(steps.ai.outputs.response).reason }}"\n',
        '      - env:\n          R: ${{ steps.ai.outputs.response }}\n'
        '        run: echo "REASON=$R" >> "$GITHUB_ENV"\n      - run: eval "$REASON"\n',
        '      - env:\n          R: ${{ steps.ai.outputs.response }}\n'
        '        run: echo "$R" > answer.txt\n      - run: bash answer.txt\n',
        '      - env:\n          R: ${{ steps.ai.outputs.response }}\n        run: echo "$R" | sh\n',
    ],
)
def test_model_text_reaching_execution_is_critical(tmp_path: Path, body: str) -> None:
    assert _severity(tmp_path, _steps(body), "AIA010") == "critical"


def test_model_text_crossing_jobs_is_tracked(tmp_path: Path) -> None:
    jobs = (
        "jobs:\n  first:\n    runs-on: ubuntu-latest\n    outputs:\n"
        "      answer: ${{ steps.ai.outputs.response }}\n    steps:" + AGENT_STEP +
        "  second:\n    needs: first\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: echo "${{ needs.first.outputs.answer }}"\n'
    )
    assert _severity(tmp_path, jobs, "AIA010") == "critical"


def test_model_text_saved_as_data_is_not_flagged(tmp_path: Path) -> None:
    body = (
        "      - env:\n          R: ${{ steps.ai.outputs.response }}\n"
        "        run: printf '%s' \"$R\" > answer.txt\n      - run: wc -c answer.txt\n"
    )
    assert "AIA010" not in _rule_ids(tmp_path, _steps(body))


@pytest.mark.parametrize(
    "with_ref",
    ["refs/pull/${{ github.event.pull_request.number }}/merge", "${{ github.event.pull_request.merge_commit_sha }}"],
)
def test_other_pr_checkout_refs_are_detected(tmp_path: Path, with_ref: str) -> None:
    jobs = f"""
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: {with_ref}
      - uses: anthropics/claude-code-action@v1.0.100
        with:
          prompt: "Review"
"""
    assert "AIA008" in _rule_ids(tmp_path, jobs, PR_TARGET_HEADER)


@pytest.mark.parametrize("command", ["gh pr checkout 12", "git fetch origin pull/12/head"])
def test_pr_checkout_commands_stay_critical(tmp_path: Path, command: str) -> None:
    jobs = f"""
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: {command}
      - uses: anthropics/claude-code-action@v1.0.100
        with:
          prompt: "Review"
"""
    assert _severity(tmp_path, jobs, "AIA008", PR_TARGET_HEADER) == "critical"


def test_base_branch_checkout_is_not_flagged(tmp_path: Path) -> None:
    jobs = """
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1.0.100
        with:
          prompt: "Review"
"""
    assert "AIA008" not in _rule_ids(tmp_path, jobs, PR_TARGET_HEADER)


def test_gh_output_is_not_model_text(tmp_path: Path) -> None:
    body = (
        "      - id: pr\n        run: |\n"
        '          pr=$(gh api "repos/x/y/pulls" --jq ".[0]")\n'
        '          echo "base_sha=$(jq -r .base.sha <<<"$pr")" >> "$GITHUB_OUTPUT"\n'
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ steps.pr.outputs.base_sha }}\n"
    )
    assert "AIA010" not in _rule_ids(tmp_path, _steps(body))


def test_event_data_is_not_model_text(tmp_path: Path) -> None:
    body = '      - run: echo "${{ github.event.issue.title }}"\n'
    assert "AIA010" not in _rule_ids(tmp_path, _steps(body))


def test_output_heredoc_is_not_mistaken_for_a_file(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        runs-on: ubuntu-latest
        steps:
          - id: issue
            run: |
              gh issue view 1 --json title,body > /tmp/issue.json
              echo "details<<EOF" >> $GITHUB_OUTPUT
              cat /tmp/issue.json >> $GITHUB_OUTPUT
              echo "EOF" >> $GITHUB_OUTPUT
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Triage ${{ steps.issue.outputs.details }}"
    """
    assert "AIA001" in _rule_ids(tmp_path, jobs)


def test_isolated_pinned_checkout_is_high(tmp_path: Path) -> None:
    extra = "\n          path: review-target\n          persist-credentials: false"
    jobs = _pr_target_job("actions/checkout@" + "a" * 40, extra)
    assert _severity(tmp_path, jobs, "AIA008", PR_TARGET_HEADER) == "high"


def test_excluding_bots_is_not_a_spoofable_check(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        if: "!endsWith(github.actor, '[bot]')"
        runs-on: ubuntu-latest
        steps:
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Review"
    """
    assert "AIA003" not in _rule_ids(tmp_path, jobs)


def test_guards_on_every_branch_are_complete(tmp_path: Path) -> None:
    jobs = """
    jobs:
      ai:
        if: github.event.label.name == 'bot' || github.event.label.name == 'bot:config'
        runs-on: ubuntu-latest
        steps:
          - uses: anthropics/claude-code-action@v1.0.100
            with:
              prompt: "Fix ${{ github.event.issue.body }}"
    """
    assert _severity(tmp_path, jobs, "AIA001") == "medium"


@pytest.mark.parametrize(
    "args",
    ['--allowedTools "Read,Grep"', '--disallowedTools "Bash,Edit"', '--allowed-tools "Read"'],
)
def test_agent_without_shell_lowers_taint_to_high(tmp_path: Path, args: str) -> None:
    header = "on:\n  issues:\n    types: [opened]\npermissions: write-all\n"
    jobs = _action_job('prompt: "Fix ${{ github.event.issue.body }}"', f"claude_args: '{args}'")
    assert _severity(tmp_path, jobs, "AIA001", header) == "high"


def test_agent_with_shell_tools_stays_critical(tmp_path: Path) -> None:
    header = "on:\n  issues:\n    types: [opened]\npermissions: write-all\n"
    jobs = _action_job('prompt: "Fix ${{ github.event.issue.body }}"', "claude_args: '--allowedTools \"Bash(gh:*)\"'")
    assert _severity(tmp_path, jobs, "AIA001", header) == "critical"


def test_isolated_opt_in_checkout_is_high(tmp_path: Path) -> None:
    extra = "\n          path: pr\n          persist-credentials: false\n          allow-unsafe-pr-checkout: true"
    jobs = _pr_target_job("actions/checkout@v4", extra)
    assert _severity(tmp_path, jobs, "AIA008", PR_TARGET_HEADER) == "high"


def test_guarded_pr_checkout_is_medium(tmp_path: Path) -> None:
    jobs = _pr_target_job("actions/checkout@" + "a" * 40).replace(
        "    runs-on: ubuntu-latest", "    if: github.event.label.name == 'review'\n    runs-on: ubuntu-latest"
    )
    assert _severity(tmp_path, jobs, "AIA008", PR_TARGET_HEADER) == "medium"


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
        'pnpm dlx @anthropic-ai/claude-code -p "$BODY" --dangerously-skip-permissions',
        'yarn dlx @anthropic-ai/claude-code -p "$BODY" --dangerously-skip-permissions',
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


def test_fixer_does_not_downgrade_branch_refs() -> None:
    source = "jobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@main\n"
    fixed, notes = apply_fixes_to_text(source)
    assert fixed == source
    assert notes == []


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

def test_google_jules_run_is_detected(tmp_path: Path) -> None:
    """Test that the audit engine successfully flags Google Jules workflows
    when untrusted user input (like an issue comment body) is passed to the prompt.
    """
    
    # 1. Define a mock GitHub Actions workflow string using Google Jules
    # with an insecure/untrusted input pattern (comment body).
    jobs = """
jobs:
  jules:
    runs-on: ubuntu-latest
    steps:
      - uses: google-labs-code/jules-action@v1
        with:
          prompt: ${{ github.event.comment.body }}
          jules_api_key: ${{ secrets.JULES_API_KEY }}
"""
    
    # 2. Feed the workflow into the test environment and verify 
    # that the core security rule AIA001 (untrusted input into AI agent) is triggered.
    assert "AIA001" in _rule_ids(tmp_path, jobs)