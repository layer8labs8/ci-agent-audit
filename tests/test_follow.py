"""Tests for following local composite actions and reusable workflows."""

from __future__ import annotations

import json
import os
from pathlib import Path
import time

import pytest

from ci_agent_audit.cli import main
from ci_agent_audit.models import Finding, Severity
from ci_agent_audit.rules import MAX_CALL_DEPTH, _describe_sources, dedupe_findings, scan_workflow_file
from site_scan import scan_text

AGENT = "anthropics/claude-code-action@v1.0.100"
READ_ONLY = "permissions:\n  contents: read"

TRIAGE_ACTION = f"""
name: Triage
inputs:
  text:
    required: true
runs:
  using: composite
  steps:
    - uses: {AGENT}
      with:
        prompt: ${{{{ inputs.text }}}}
"""

CALLS_TRIAGE = """
on: [issues]
{permissions}
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/triage
        with:
          text: ${{{{ github.event.issue.body }}}}
"""


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root / ".github" / "workflows" / "ai.yml"


def _rules(path: Path) -> set[str]:
    return {finding.rule_id for finding in scan_workflow_file(path)}


def _finding(path: Path, rule_id: str) -> Finding:
    return next(finding for finding in scan_workflow_file(path) if finding.rule_id == rule_id)


def _triage_repo(root: Path, permissions: str = "") -> Path:
    return _repo(
        root,
        {
            ".github/workflows/ai.yml": CALLS_TRIAGE.format(permissions=permissions),
            ".github/actions/triage/action.yml": TRIAGE_ACTION,
        },
    )


def test_finding_points_at_the_action_file(tmp_path: Path) -> None:
    finding = _finding(_triage_repo(tmp_path), "AIA001")
    assert finding.file_path.as_posix().endswith(".github/actions/triage/action.yml")
    assert finding.snippet == "prompt: ${{ inputs.text }}"
    assert "Reached from" in finding.message and "ai.yml" in finding.message


def test_action_finding_uses_the_workflow_trigger(tmp_path: Path) -> None:
    assert _finding(_triage_repo(tmp_path), "AIA001").severity is Severity.CRITICAL


def test_read_only_token_lowers_an_action_finding(tmp_path: Path) -> None:
    path = _triage_repo(tmp_path, "permissions:\n  contents: read")
    assert _finding(path, "AIA001").severity is Severity.HIGH


def test_job_level_finding_points_at_the_agent_step_file(tmp_path: Path) -> None:
    finding = _finding(_triage_repo(tmp_path), "AIA006")
    assert finding.file_path.name == "action.yml"
    assert finding.snippet == f"- uses: {AGENT}"


def test_second_action_does_not_see_the_first_actions_inputs(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": """
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/log
        with:
          text: ${{ github.event.issue.body }}
      - uses: ./.github/actions/triage
        with:
          text: "Check the build."
""",
            ".github/actions/log/action.yml": """
name: Log
inputs:
  text:
    required: true
runs:
  using: composite
  steps:
    - shell: bash
      run: echo done
""",
            ".github/actions/triage/action.yml": TRIAGE_ACTION,
        },
    )
    assert "AIA001" not in _rules(path)


def test_action_inputs_do_not_leak_back_to_the_job(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": f"""
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/log
        with:
          text: ${{{{ github.event.issue.body }}}}
      - uses: {AGENT}
        with:
          prompt: ${{{{ inputs.text }}}}
""",
            ".github/actions/log/action.yml": """
name: Log
runs:
  using: composite
  steps:
    - shell: bash
      run: echo done
""",
        },
    )
    assert "AIA001" not in _rules(path)


def test_step_ids_inside_an_action_stay_private(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": f"""
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/read
      - id: read
        run: echo "text=hello" >> "$GITHUB_OUTPUT"
      - uses: {AGENT}
        with:
          prompt: ${{{{ steps.read.outputs.text }}}}
""",
            ".github/actions/read/action.yml": """
name: Read
runs:
  using: composite
  steps:
    - id: read
      shell: bash
      env:
        BODY: ${{ github.event.issue.body }}
      run: echo "text=$BODY" >> "$GITHUB_OUTPUT"
""",
        },
    )
    assert "AIA001" not in _rules(path)


def test_caller_step_env_reaches_the_action(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": """
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/run
        env:
          BODY: ${{ github.event.issue.body }}
""",
            ".github/actions/run/action.yml": """
name: Run
runs:
  using: composite
  steps:
    - shell: bash
      run: claude -p "Triage $BODY"
""",
        },
    )
    assert "AIA001" in _rules(path)


def test_caller_step_env_ends_with_the_call(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": """
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/log
        env:
          BODY: ${{ github.event.issue.body }}
      - run: claude -p "Triage $BODY"
""",
            ".github/actions/log/action.yml": """
name: Log
runs:
  using: composite
  steps:
    - shell: bash
      run: echo done
""",
        },
    )
    assert "AIA001" not in _rules(path)


def test_env_exported_by_an_action_reaches_later_steps(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": f"""
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/read
      - uses: {AGENT}
        with:
          prompt: ${{{{ env.TASK }}}}
""",
            ".github/actions/read/action.yml": """
name: Read
runs:
  using: composite
  steps:
    - shell: bash
      env:
        BODY: ${{ github.event.issue.body }}
      run: echo "TASK=$BODY" >> "$GITHUB_ENV"
""",
        },
    )
    assert "AIA001" in _rules(path)


def test_model_output_passed_to_an_action_is_tracked(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": """
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - id: ai
        uses: actions/ai-inference@v1.2.0
        with:
          prompt: "Suggest a command."
      - uses: ./.github/actions/execute
        with:
          command: ${{ steps.ai.outputs.response }}
""",
            ".github/actions/execute/action.yml": """
name: Execute
inputs:
  command:
    required: true
runs:
  using: composite
  steps:
    - shell: bash
      run: ${{ inputs.command }}
""",
        },
    )
    assert _finding(path, "AIA010").file_path.name == "action.yml"


@pytest.mark.parametrize("name", ["action.yml", "action.yaml"])
def test_both_action_file_names_work(tmp_path: Path, name: str) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": CALLS_TRIAGE.format(permissions=""),
            f".github/actions/triage/{name}": TRIAGE_ACTION,
        },
    )
    assert "AIA001" in _rules(path)


def test_javascript_action_is_left_alone(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": CALLS_TRIAGE.format(permissions=""),
            ".github/actions/triage/action.yml": "name: JS\nruns:\n  using: node20\n  main: index.js\n",
        },
    )
    assert _rules(path) == set()


def test_missing_action_is_skipped(tmp_path: Path) -> None:
    path = _repo(tmp_path, {".github/workflows/ai.yml": CALLS_TRIAGE.format(permissions="")})
    assert _rules(path) == set()


def test_broken_action_does_not_stop_the_workflow_scan(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": f"""
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/broken
      - uses: {AGENT}
        with:
          prompt: ${{{{ github.event.issue.body }}}}
""",
            ".github/actions/broken/action.yml": "runs: [unclosed",
        },
    )
    assert "AIA001" in _rules(path)


def test_action_that_calls_itself_ends(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": CALLS_TRIAGE.format(permissions=""),
            ".github/actions/triage/action.yml": f"""
name: Loop
inputs:
  text:
    required: true
runs:
  using: composite
  steps:
    - uses: ./.github/actions/triage
      with:
        text: ${{{{ inputs.text }}}}
    - uses: {AGENT}
      with:
        prompt: ${{{{ inputs.text }}}}
""",
        },
    )
    assert "AIA001" in _rules(path)


def test_workflows_that_call_each_other_end(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": """
on: [workflow_call, issues]
jobs:
  next:
    uses: ./.github/workflows/other.yml
""",
            ".github/workflows/other.yml": """
on: [workflow_call]
jobs:
  back:
    uses: ./.github/workflows/ai.yml
""",
        },
    )
    assert _rules(path) == set()


def test_call_depth_is_limited(tmp_path: Path) -> None:
    files = {".github/workflows/ai.yml": CALLS_TRIAGE.format(permissions="").replace("triage", "a0")}
    depth = MAX_CALL_DEPTH + 3
    for level in range(depth):
        files[f".github/actions/a{level}/action.yml"] = f"""
name: Level
inputs:
  text:
    required: true
runs:
  using: composite
  steps:
    - uses: ./.github/actions/a{level + 1}
      with:
        text: ${{{{ inputs.text }}}}
"""
    files[f".github/actions/a{depth}/action.yml"] = TRIAGE_ACTION
    assert _rules(_repo(tmp_path, files)) == set()


def test_crafted_fan_out_finishes(tmp_path: Path) -> None:
    calls = "\n".join("    - uses: ./.github/actions/a{next}" for _ in range(10))
    files = {".github/workflows/ai.yml": CALLS_TRIAGE.format(permissions="").replace("triage", "a0")}
    for level in range(9):
        steps = calls.format(next=level + 1)
        files[f".github/actions/a{level}/action.yml"] = f"name: Fan\nruns:\n  using: composite\n  steps:\n{steps}\n"
    path = _repo(tmp_path, files)
    started = time.monotonic()
    scan_workflow_file(path)
    assert time.monotonic() - started < 30


def test_path_outside_the_repository_is_not_followed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    path = _repo(
        repo,
        {
            ".github/workflows/ai.yml": """
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: ./../outside
        with:
          text: ${{ github.event.issue.body }}
""",
        },
    )
    _repo(tmp_path, {"outside/action.yml": TRIAGE_ACTION})
    assert _rules(path) == set()


def test_symlink_out_of_the_repository_is_not_followed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    path = _repo(repo, {".github/workflows/ai.yml": CALLS_TRIAGE.format(permissions="")})
    _repo(tmp_path, {"outside/action.yml": TRIAGE_ACTION})
    link = repo / ".github" / "actions" / "triage"
    link.parent.mkdir(parents=True)
    try:
        os.symlink(tmp_path / "outside", link, target_is_directory=True)
    except OSError:
        pytest.skip("This system can't create symlinks.")
    assert _rules(path) == set()


def test_file_outside_github_workflows_follows_nothing(tmp_path: Path) -> None:
    path = tmp_path / "wf.yml"
    path.write_text(CALLS_TRIAGE.format(permissions=""), encoding="utf-8")
    _repo(tmp_path, {".github/actions/triage/action.yml": TRIAGE_ACTION})
    assert _rules(path) == set()


REUSABLE = f"""
on:
  workflow_call:
    inputs:
      text:
        type: string
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: {AGENT}
        with:
          prompt: "Triage ${{{{ inputs.text }}}} ${{{{ github.event.issue.title }}}}"
"""

CALLS_REUSABLE = """
on: [issues]
jobs:
  ai:
    uses: ./.github/workflows/agent.yml
    with:
      text: ${{ github.event.issue.body }}
"""


def test_reusable_workflow_alone_is_gated_but_a_public_caller_is_not(tmp_path: Path) -> None:
    path = _repo(tmp_path, {".github/workflows/ai.yml": CALLS_REUSABLE, ".github/workflows/agent.yml": REUSABLE})
    assert _finding(path.with_name("agent.yml"), "AIA001").severity is Severity.HIGH
    assert _finding(path, "AIA001").severity is Severity.CRITICAL


def test_reusable_workflow_does_not_inherit_the_callers_env(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": """
on: [issues]
env:
  TEXT: ${{ github.event.issue.body }}
jobs:
  ai:
    uses: ./.github/workflows/agent.yml
""",
            ".github/workflows/agent.yml": f"""
on: [workflow_call]
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: {AGENT}
        with:
          prompt: ${{{{ env.TEXT }}}}
""",
        },
    )
    assert "AIA001" not in _rules(path)


def test_caller_job_permissions_limit_a_reusable_workflow(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": """
on: [issues]
jobs:
  ai:
    permissions:
      contents: read
    uses: ./.github/workflows/agent.yml
""",
            ".github/workflows/agent.yml": REUSABLE,
        },
    )
    assert "AIA005" not in _rules(path)


def test_step_condition_on_a_call_counts_as_a_guard(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": """
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - if: github.event.issue.author_association == 'OWNER'
        uses: ./.github/actions/triage
        with:
          text: ${{ github.event.issue.body }}
""",
            ".github/actions/triage/action.yml": TRIAGE_ACTION,
        },
    )
    assert _finding(path, "AIA001").severity is Severity.MEDIUM


def test_guard_with_an_or_on_a_caller_stays_a_guard_only_if_complete(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": """
on: [issues]
jobs:
  ai:
    if: github.event.issue.author_association == 'OWNER' || github.event.action == 'opened'
    uses: ./.github/workflows/agent.yml
    with:
      text: ${{ github.event.issue.body }}
""",
            ".github/workflows/agent.yml": REUSABLE,
        },
    )
    assert _finding(path, "AIA001").severity is Severity.HIGH


def test_or_around_a_guard_inside_parentheses_is_not_complete(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": f"""
on: [issues]
permissions:
  contents: read
jobs:
  ai:
    if: (github.event.issue.author_association == 'OWNER' || github.event.action == 'opened') && github.repository == 'a/b'
    runs-on: ubuntu-latest
    steps:
      - uses: {AGENT}
        with:
          prompt: ${{{{ github.event.issue.body }}}}
""",
        },
    )
    assert _finding(path, "AIA001").severity is Severity.HIGH


def test_needed_job_chain_carries_a_guard(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": f"""
on: [issues]
permissions:
  contents: read
jobs:
  check:
    if: github.event.issue.author_association == 'OWNER'
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
  middle:
    needs: check
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
  ai:
    needs: [middle]
    runs-on: ubuntu-latest
    steps:
      - uses: {AGENT}
        with:
          prompt: ${{{{ github.event.issue.body }}}}
""",
        },
    )
    assert _finding(path, "AIA001").severity is Severity.MEDIUM


def test_guarded_caller_replaces_the_alone_scan_of_a_reusable_workflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": """
on: [issues]
jobs:
  ai:
    if: github.event.issue.author_association == 'OWNER'
    uses: ./.github/workflows/agent.yml
""",
            ".github/workflows/agent.yml": f"""
on: [workflow_call]
permissions:
  contents: read
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: {AGENT}
        with:
          prompt: ${{{{ github.event.issue.body }}}}
""",
        },
    )
    monkeypatch.chdir(tmp_path)
    main(["scan", "--format", "json", "--fail-on", "none"])
    output = capsys.readouterr().out
    assert '"severity": "medium"' in output and '"severity": "high"' not in output


def test_long_source_chain_is_shortened() -> None:
    chain = "gh CLI output (via env.A) (via env.B) (via env.C) (via inputs.prompt)"
    assert _describe_sources([chain]) == "gh CLI output (via env.A) ... (via inputs.prompt)"
    assert _describe_sources([f"s{n}" for n in range(5)]) == "s0, s1, s2 and 2 more"


def test_many_sources_reach_one_sink_as_one_finding(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": CALLS_TRIAGE.format(permissions="").replace(
                "      - uses: ./.github/actions/triage",
                "      - uses: ./.github/actions/triage\n"
                "        with:\n          text: ${{ github.event.issue.title }}\n"
                "      - uses: ./.github/actions/triage",
            ),
            ".github/actions/triage/action.yml": TRIAGE_ACTION,
        },
    )
    assert len([finding for finding in scan_workflow_file(path) if finding.rule_id == "AIA001"]) == 1


NEEDED_JOB = """
on: [issues]
jobs:
  check:
    runs-on: ubuntu-latest
    steps: {steps}
  ai:
    needs: check
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
"""


@pytest.mark.parametrize("steps", ["5", "true", "text", "null", "{}"])
def test_needed_job_with_broken_steps_does_not_crash(tmp_path: Path, steps: str) -> None:
    assert _rules(_repo(tmp_path, {".github/workflows/ai.yml": NEEDED_JOB.format(steps=steps)})) == set()


PERMISSION_STEP = """
on: [issue_comment]
permissions:
  contents: read
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - {extra}run: |
          perm=$(gh api "repos/$GITHUB_REPOSITORY/collaborators/$GITHUB_ACTOR/permission" --jq .permission){check}
      - uses: anthropics/claude-code-action@v1.0.100
        with:
          prompt: ${{{{ github.event.comment.body }}}}
"""
BLOCKS = """
          if [ "$perm" != admin ]; then exit 1; fi"""


def test_permission_check_that_stops_the_job_is_a_guard(tmp_path: Path) -> None:
    path = _repo(tmp_path, {".github/workflows/ai.yml": PERMISSION_STEP.format(extra="", check=BLOCKS)})
    assert _finding(path, "AIA001").severity is Severity.MEDIUM


@pytest.mark.parametrize(
    ("extra", "check"),
    [
        ("if: github.event_name == 'push'\n        ", BLOCKS),
        ("continue-on-error: true\n        ", BLOCKS),
        ("", " || exit 1"),
    ],
    ids=["skipped-on-some-paths", "failure-ignored", "level-never-compared"],
)
def test_permission_check_that_can_be_passed_is_no_guard(tmp_path: Path, extra: str, check: str) -> None:
    path = _repo(tmp_path, {".github/workflows/ai.yml": PERMISSION_STEP.format(extra=extra, check=check)})
    assert _finding(path, "AIA001").severity is Severity.HIGH


def test_safe_jq_field_does_not_clean_the_rest_of_the_line(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": f"""
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - id: mix
        env:
          BODY: ${{{{ github.event.issue.body }}}}
        run: |
          pr=$(gh api "repos/$GITHUB_REPOSITORY/pulls/1")
          echo "text=$BODY $(echo "$pr" | jq -r .number)" >> "$GITHUB_OUTPUT"
      - uses: {AGENT}
        with:
          prompt: ${{{{ steps.mix.outputs.text }}}}
""",
        },
    )
    assert "AIA001" in _rules(path)


def test_directory_scan_reports_a_shared_action_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _triage_repo(tmp_path)
    _repo(tmp_path, {".github/workflows/second.yml": CALLS_TRIAGE.format(permissions="")})
    monkeypatch.chdir(tmp_path)
    assert main(["scan", "--format", "json", "--output", "out.json", "--fail-on", "none"]) == 0
    data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    findings = data if isinstance(data, list) else data["findings"]
    rows = [finding for finding in findings if finding["rule_id"] == "AIA001"]
    assert len(rows) == 1
    assert rows[0]["file"] == ".github/actions/triage/action.yml"


def test_directory_scan_keeps_the_worst_severity_of_a_reusable_workflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _repo(tmp_path, {".github/workflows/ai.yml": CALLS_REUSABLE, ".github/workflows/agent.yml": REUSABLE})
    monkeypatch.chdir(tmp_path)
    main(["scan", "--format", "json", "--fail-on", "none"])
    assert '"severity": "critical"' in capsys.readouterr().out


def test_ignore_comment_in_the_action_file_works(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": CALLS_TRIAGE.format(permissions=READ_ONLY),
            ".github/actions/triage/action.yml": TRIAGE_ACTION.replace(
                f"    - uses: {AGENT}", f"    # ci-agent-audit: ignore AIA001, AIA006\n    - uses: {AGENT}"
            ),
        },
    )
    monkeypatch.chdir(tmp_path)
    assert main(["scan", "--fail-on", "medium"]) == 0
    assert main(["scan", "--fail-on", "medium", "--no-ignore"]) == 1


def test_config_can_ignore_a_finding_in_an_action_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _triage_repo(tmp_path, READ_ONLY)
    (tmp_path / ".ci-agent-audit.yml").write_text(
        "ignore:\n"
        "  - rule: AIA001\n    path: .github/actions/triage/action.yml\n    reason: Reviewed\n"
        "  - rule: AIA006\n    path: .github/actions/triage/action.yml\n    reason: Reviewed\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    assert main(["scan", "--fail-on", "medium"]) == 0


def test_dedupe_keeps_different_messages_on_one_line(tmp_path: Path) -> None:
    path = tmp_path / "wf.yml"
    base = {"rule_id": "AIA002", "rule_name": "x", "file_path": path, "line": 3, "column": 1, "remediation": ""}
    first = Finding(severity=Severity.HIGH, message="flag one", **base)
    second = Finding(severity=Severity.HIGH, message="flag two", **base)
    assert len(dedupe_findings([first, second])) == 2


def test_dedupe_keeps_the_worst_copy(tmp_path: Path) -> None:
    path = tmp_path / "wf.yml"
    base = {"rule_id": "AIA001", "rule_name": "x", "file_path": path, "line": 3, "column": 1, "remediation": ""}
    low = Finding(severity=Severity.HIGH, message="same", **base)
    high = Finding(severity=Severity.CRITICAL, message="same", **base)
    assert dedupe_findings([low, high]) == [high]


def test_bracket_syntax_works_for_step_outputs(tmp_path: Path) -> None:
    path = _repo(
        tmp_path,
        {
            ".github/workflows/ai.yml": f"""
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - id: read
        env:
          BODY: ${{{{ github.event.issue.body }}}}
        run: echo "text=$BODY" >> "$GITHUB_OUTPUT"
      - uses: {AGENT}
        with:
          prompt: ${{{{ steps['read'].outputs['text'] }}}}
""",
        },
    )
    assert "AIA001" in _rules(path)


def test_site_says_when_a_workflow_calls_local_files() -> None:
    assert json.loads(scan_text(CALLS_TRIAGE.format(permissions="")))["local_calls"] is True
    assert json.loads(scan_text("on: [push]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: ls\n"))[
        "local_calls"
    ] is False
