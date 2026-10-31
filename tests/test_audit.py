"""Comprehensive test suite for ci-agent-audit."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from ci_agent_audit.cli import main
from ci_agent_audit.fixer import apply_fixes_to_text
from ci_agent_audit.rules import scan_workflow_file
from ci_agent_audit.signatures_loader import SignatureValidationError, load_signatures, parse_signature_dict


def test_builtin_signatures_load_and_validate() -> None:
    sigs = load_signatures()
    assert len(sigs) >= 12
    ids = {s.id for s in sigs}
    assert "claude-code-action" in ids
    assert "run-gemini-cli" in ids
    assert "codex-action" in ids


def test_invalid_signature_rejected() -> None:
    with pytest.raises(SignatureValidationError):
        parse_signature_dict({"id": "broken-only"})


def test_detects_promptpwnd_direct_and_bot_bypass_and_version(tmp_path: Path) -> None:
    wf = tmp_path / "vulnerable_claude.yml"
    wf.write_text(
        """
name: Vulnerable Triage
on:
  issues:
    types: [opened]

permissions: write-all

jobs:
  triage:
    if: endsWith(github.actor, '[bot]')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Claude
        uses: anthropics/claude-code-action@v1.0.80
        with:
          direct_prompt: "Triage this issue: ${{ github.event.issue.body }}"
          allowed_non_write_users: "*"
          claude_args: "--dangerously-skip-permissions"
""",
        encoding="utf-8",
    )

    findings = scan_workflow_file(wf)
    rule_ids = {f.rule_id for f in findings}
    assert "AIA001" in rule_ids  # PromptPwnd via github.event.issue.body
    assert "AIA002" in rule_ids  # --dangerously-skip-permissions
    assert "AIA003" in rule_ids  # endsWith [bot] and allowed_non_write_users: "*"
    assert "AIA004" in rule_ids  # v1.0.80 < v1.0.94
    assert "AIA005" in rule_ids  # permissions: write-all
    assert "AIA006" in rule_ids  # missing egress firewall


def test_detects_two_hop_env_taint_and_unpinned_mcp(tmp_path: Path) -> None:
    wf = tmp_path / "gemini_env_taint.yml"
    wf.write_text(
        """
name: Gemini PR Helper
on: [issue_comment]

permissions:
  contents: read

jobs:
  assist:
    runs-on: ubuntu-24.04-firewall
    env:
      RAW_COMMENT: ${{ github.event.comment.body }}
    steps:
      - name: Setup MCP and run Gemini CLI
        env:
          USER_PROMPT: "Handle request: $RAW_COMMENT"
        run: |
          npx -y @modelcontextprotocol/server-github
          gemini --yolo -p "$USER_PROMPT"
""",
        encoding="utf-8",
    )

    findings = scan_workflow_file(wf)
    rule_ids = {f.rule_id for f in findings}
    assert "AIA001" in rule_ids  # 2-hop env taint RAW_COMMENT -> USER_PROMPT -> gemini
    assert "AIA002" in rule_ids  # --yolo
    assert "AIA007" in rule_ids  # unpinned npx -y @modelcontextprotocol/server-github
    assert "AIA005" not in rule_ids  # permissions: contents: read is least-privilege
    assert "AIA006" not in rule_ids  # ubuntu-24.04-firewall satisfies egress check


def test_detects_pull_request_target_checkout_with_ai_agent(tmp_path: Path) -> None:
    wf = tmp_path / "pr_target.yml"
    wf.write_text(
        """
name: PR Review
on: [pull_request_target]

permissions:
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@v2
        with:
          egress-policy: block
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: openai/codex-action@v1.2.0
        with:
          prompt: "Review the checked out files."
""",
        encoding="utf-8",
    )

    findings = scan_workflow_file(wf)
    rule_ids = {f.rule_id for f in findings}
    assert "AIA008" in rule_ids


def test_hardened_workflow_produces_zero_findings(tmp_path: Path) -> None:
    wf = tmp_path / "hardened.yml"
    wf.write_text(
        """
name: Hardened AI Review
on:
  pull_request:
    types: [opened]

permissions:
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@v2
        with:
          egress-policy: block
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1.0.94
        with:
          prompt: "Review the git diff for security bugs."
""",
        encoding="utf-8",
    )

    findings = scan_workflow_file(wf)
    assert findings == []


def test_gitlab_ci_taint_detection(tmp_path: Path) -> None:
    gl = tmp_path / ".gitlab-ci.yml"
    gl.write_text(
        """
ai_mr_review:
  variables:
    MR_BODY: $CI_MERGE_REQUEST_DESCRIPTION
  script:
    - claude --dangerously-skip-permissions -p "Review MR: $MR_BODY"
""",
        encoding="utf-8",
    )
    findings = scan_workflow_file(gl)
    rule_ids = {f.rule_id for f in findings}
    assert "AIA001" in rule_ids
    assert "AIA002" in rule_ids

def test_gitlab_ci_unpinned_mcp_detection(tmp_path: Path) -> None:
    gl = tmp_path / ".gitlab-ci.yml"
    gl.write_text(
        """
review:
  script:
    - npx -y @modelcontextprotocol/server-github
""",
        encoding="utf-8",
    )

    findings = scan_workflow_file(gl)
    rule_ids = {f.rule_id for f in findings}
    assert "AIA007" in rule_ids


def test_gitlab_ci_pinned_mcp_not_flagged(tmp_path: Path) -> None:
    gl = tmp_path / ".gitlab-ci.yml"
    gl.write_text(
        """
review:
  script:
    - npx -y @modelcontextprotocol/server-github@1.2.0
""",
        encoding="utf-8",
    )

    findings = scan_workflow_file(gl)
    rule_ids = {f.rule_id for f in findings}
    assert "AIA007" not in rule_ids

    
def test_fixer_remediates_version_wildcard_and_permissions() -> None:
    raw = """name: Demo
permissions: write-all
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1.0.50
        with:
          allowed_non_write_users: "*"
"""
    fixed, notes = apply_fixes_to_text(raw)
    assert "@v1.0.94" in fixed
    assert 'allowed_non_write_users: ""' in fixed
    assert "contents: read" in fixed
    assert len(notes) == 3


def test_cli_sarif_and_validate_signatures(tmp_path: Path) -> None:
    assert main(["validate-signatures"]) == 0

    wf = tmp_path / "bad.yml"
    wf.write_text(
        """
on: [issues]
jobs:
  run_ai:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@main
        with:
          prompt: "${{ github.event.issue.body }}"
""",
        encoding="utf-8",
    )
    sarif_out = tmp_path / "out.sarif"
    rc = main(["scan", str(wf), "--format", "sarif", "--output", str(sarif_out)])
    assert rc == 1
    sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) >= 2
