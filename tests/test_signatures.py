"""Put every tool signature through the same detection tests."""

from __future__ import annotations

from pathlib import Path
import re

import pytest

from ci_agent_audit.models import ActionSignature
from ci_agent_audit.rules import scan_workflow_file
from ci_agent_audit.signatures_loader import load_signatures

SIGNATURES = load_signatures()
HEADER = "on: [issues]\npermissions:\n  contents: read\n"
BODY = "${{ github.event.issue.body }}"


def _rules(tmp_path: Path, steps: str) -> set[str]:
    path = tmp_path / "wf.yml"
    path.write_text(f"{HEADER}jobs:\n  ai:\n    runs-on: ubuntu-latest\n    steps:\n{steps}", encoding="utf-8")
    return {finding.rule_id for finding in scan_workflow_file(path)}


def _action_step(prefix: str, key: str, value: str) -> str:
    return f"      - uses: {prefix}@v1.2.3\n        with:\n          {key}: {value!r}\n"


def _run_step(command: str) -> str:
    return f"      - env:\n          BODY: {BODY}\n        run: {command}\n"


def _command(signature: ActionSignature, binary: str) -> str:
    return f"{binary} {signature.cli_subcommands[0]}" if signature.cli_subcommands else binary


def _sample(pattern: str) -> str:
    """Turn a flag pattern back into text it matches."""
    for regex, text in (("(?:^|\\s)", ""), ("(?:\\s|$)", ""), ("[=\\s]+", "="), ("\\s+", " ")):
        pattern = pattern.replace(regex, text)
    return pattern.replace("\\", "")


def _ids(rows: list[tuple]) -> list[str]:
    return [" ".join(str(part) for part in row[1:]) for row in rows]


PROMPTS = [(s, p, key) for s in SIGNATURES for p in s.action_prefixes for key in s.prompt_inputs]
BINARIES = [(s, binary) for s in SIGNATURES for binary in s.cli_binaries]
PACKAGES = [(s, package) for s in SIGNATURES for package in s.cli_packages]
PATTERNS = [(s, flag.pattern) for s in SIGNATURES for flag in s.dangerous_arg_patterns]
INPUTS = [(s, key, value) for s in SIGNATURES for key, value in s.dangerous_inputs.items()]


def test_all_tools_are_covered() -> None:
    covered = {row[0].id for table in (PROMPTS, BINARIES) for row in table}
    assert covered == {signature.id for signature in SIGNATURES}


@pytest.mark.parametrize(("signature", "prefix", "key"), PROMPTS, ids=_ids(PROMPTS))
def test_every_prompt_input_is_checked(tmp_path: Path, signature: ActionSignature, prefix: str, key: str) -> None:
    assert "AIA001" in _rules(tmp_path, _action_step(prefix, key, f"Task: {BODY}"))


@pytest.mark.parametrize(("signature", "binary"), BINARIES, ids=_ids(BINARIES))
def test_every_command_is_detected(tmp_path: Path, signature: ActionSignature, binary: str) -> None:
    assert "AIA001" in _rules(tmp_path, _run_step(f'{_command(signature, binary)} "$BODY"'))


@pytest.mark.parametrize(("signature", "binary"), BINARIES, ids=_ids(BINARIES))
def test_a_folder_with_the_command_name_is_not_detected(
    tmp_path: Path, signature: ActionSignature, binary: str
) -> None:
    assert "AIA001" not in _rules(tmp_path, _run_step(f'python3 tools/{binary}/run.py "$BODY"'))


@pytest.mark.parametrize(("signature", "package"), PACKAGES, ids=_ids(PACKAGES))
def test_every_package_is_detected(tmp_path: Path, signature: ActionSignature, package: str) -> None:
    assert "AIA001" in _rules(tmp_path, _run_step(f'npx {package} "$BODY"'))


@pytest.mark.parametrize(("signature", "pattern"), PATTERNS, ids=_ids(PATTERNS))
def test_every_dangerous_flag_is_detected(tmp_path: Path, signature: ActionSignature, pattern: str) -> None:
    sample = _sample(pattern)
    assert re.search(pattern, sample), "Teach _sample() this pattern."
    if signature.cli_binaries:
        step = _run_step(f"{_command(signature, signature.cli_binaries[0])} {sample}")
    else:
        step = _action_step(signature.action_prefixes[0], "args", sample)
    assert "AIA002" in _rules(tmp_path, step)


@pytest.mark.parametrize(("signature", "key", "value"), INPUTS, ids=_ids(INPUTS))
def test_every_dangerous_input_is_detected(tmp_path: Path, signature: ActionSignature, key: str, value: str) -> None:
    assert _rules(tmp_path, _action_step(signature.action_prefixes[0], key, value)) & {"AIA002", "AIA003"}
