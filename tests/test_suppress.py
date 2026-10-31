"""Tests for inline ignore comments and the config file."""

from __future__ import annotations

from pathlib import Path

import pytest

from ci_agent_audit.cli import main
from ci_agent_audit.suppress import ConfigError, load_config

WORKFLOW = """
on: [issues]
permissions:
  contents: read
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      {comment}
      - uses: anthropics/claude-code-action@v1.0.100
        with:
          prompt: "Triage ${{{{ github.event.issue.body }}}}"{trailing}
"""


def _workflow(tmp_path: Path, comment: str = "- run: echo hello", trailing: str = "") -> Path:
    path = tmp_path / "wf.yml"
    path.write_text(WORKFLOW.format(comment=comment, trailing=trailing), encoding="utf-8")
    return path


def test_finding_fails_without_an_ignore(tmp_path: Path) -> None:
    assert main(["scan", str(_workflow(tmp_path)), "--fail-on", "high"]) == 1


def test_inline_comment_on_the_line_ignores_the_rule(tmp_path: Path) -> None:
    path = _workflow(tmp_path, trailing="  # ci-agent-audit: ignore AIA001")
    assert main(["scan", str(path), "--fail-on", "high", "--ignore-rule", "AIA006"]) == 0


def test_comment_above_the_step_ignores_the_rule(tmp_path: Path) -> None:
    path = _workflow(tmp_path, comment="# ci-agent-audit: ignore AIA006")
    capture = tmp_path / "out.json"
    main(["scan", str(path), "--format", "json", "--fail-on", "none", "--output", str(capture)])
    assert "AIA006" not in capture.read_text(encoding="utf-8")


def test_comment_above_a_step_covers_its_with_block(tmp_path: Path) -> None:
    path = _workflow(tmp_path, comment="# ci-agent-audit: ignore AIA001, AIA006")
    assert main(["scan", str(path), "--fail-on", "low"]) == 0


def test_step_comment_does_not_cover_other_steps(tmp_path: Path) -> None:
    path = tmp_path / "wf.yml"
    path.write_text(
        """
on: [issues]
permissions:
  contents: read
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      # ci-agent-audit: ignore AIA001
      - run: echo hello
      - uses: anthropics/claude-code-action@v1.0.100
        with:
          prompt: "Triage ${{ github.event.issue.body }}"
""",
        encoding="utf-8",
    )
    assert main(["scan", str(path), "--fail-on", "high"]) == 1


def test_inline_comment_only_covers_named_rules(tmp_path: Path) -> None:
    path = _workflow(tmp_path, trailing="  # ci-agent-audit: ignore AIA006")
    assert main(["scan", str(path), "--fail-on", "high"]) == 1


def test_comment_without_a_rule_ignores_nothing(tmp_path: Path) -> None:
    path = _workflow(tmp_path, trailing="  # ci-agent-audit: ignore")
    assert main(["scan", str(path), "--fail-on", "high"]) == 1


def test_config_file_ignores_a_rule_for_a_path(tmp_path: Path) -> None:
    path = _workflow(tmp_path)
    config = tmp_path / "audit.yml"
    config.write_text(
        "ignore:\n"
        "  - rule: AIA001\n    path: wf.yml\n    reason: Reviewed by security\n"
        "  - rule: AIA006\n    reason: Runner blocks egress\n",
        encoding="utf-8",
    )
    assert main(["scan", str(path), "--fail-on", "low", "--config", str(config)]) == 0


def test_config_for_another_path_does_not_apply(tmp_path: Path) -> None:
    path = _workflow(tmp_path)
    config = tmp_path / "audit.yml"
    config.write_text("ignore:\n  - rule: AIA001\n    path: other.yml\n    reason: Not this file\n", encoding="utf-8")
    assert main(["scan", str(path), "--fail-on", "high", "--config", str(config)]) == 1


def test_default_config_is_loaded_from_the_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _workflow(tmp_path)
    (tmp_path / ".ci-agent-audit.yml").write_text(
        "ignore:\n  - rule: AIA001\n    reason: Reviewed\n  - rule: AIA006\n    reason: Reviewed\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert main(["scan", str(path), "--fail-on", "low"]) == 0


def test_no_ignore_shows_everything(tmp_path: Path) -> None:
    path = _workflow(tmp_path, trailing="  # ci-agent-audit: ignore AIA001")
    assert main(["scan", str(path), "--fail-on", "high", "--no-ignore"]) == 1


def test_ignored_count_is_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _workflow(tmp_path, trailing="  # ci-agent-audit: ignore AIA001")
    main(["scan", str(path), "--fail-on", "none"])
    assert "1 finding(s) ignored" in capsys.readouterr().err


@pytest.mark.parametrize(
    "text",
    [
        "ignore:\n  - rule: AIA001\n",
        "ignore:\n  - reason: Missing rule\n",
        "ignore:\n  - rule: nope\n    reason: Bad rule\n",
        "ignore: nope\n",
        "- not a mapping\n",
    ],
)
def test_invalid_config_is_rejected(tmp_path: Path, text: str) -> None:
    config = tmp_path / "audit.yml"
    config.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(config)


def test_invalid_config_stops_the_scan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "audit.yml"
    config.write_text("ignore:\n  - rule: AIA001\n", encoding="utf-8")
    assert main(["scan", str(_workflow(tmp_path)), "--config", str(config)]) == 2
    assert "needs a rule" in capsys.readouterr().err


def test_missing_named_config_stops_the_scan(tmp_path: Path) -> None:
    assert main(["scan", str(_workflow(tmp_path)), "--config", str(tmp_path / "missing.yml")]) == 2
