"""Tests for the project website."""

from __future__ import annotations

import json
from pathlib import Path
import zipfile

import pytest

from build_site import QUESTIONS, SUPPORT, build
from ci_agent_audit import __version__
from ci_agent_audit.rules import RULES_CATALOG
from site_scan import scan_text


@pytest.fixture(scope="module")
def site(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("site") / "_site"
    build(out)
    return out


def _examples(site: Path) -> dict[str, dict]:
    page = (site / "index.html").read_text(encoding="utf-8")
    raw = page.split('<script id="examples" type="application/json">')[1].split("</script>")[0]
    return {example["slug"]: example for example in json.loads(raw)}


def test_every_rule_has_a_question() -> None:
    assert set(QUESTIONS) == set(RULES_CATALOG)


def test_page_has_no_unfilled_tokens(site: Path) -> None:
    assert "<!-- " not in (site / "index.html").read_text(encoding="utf-8")


def test_page_lists_rules_and_version(site: Path) -> None:
    page = (site / "index.html").read_text(encoding="utf-8")
    assert all(f'<tr id="{rule_id}">' in page for rule_id in RULES_CATALOG)
    assert f"layer8labs8/ci-agent-audit@v{__version__}" in page


def test_page_shows_each_support_address(site: Path) -> None:
    page = (site / "index.html").read_text(encoding="utf-8")
    assert page.count('id="support"') == 1
    assert all(f'data-copy="{address}"' in page for _, address in SUPPORT)


def test_page_shows_the_benchmark(site: Path) -> None:
    page = (site / "index.html").read_text(encoding="utf-8")
    assert "<th scope=\"row\">Local composite actions</th>" in page
    assert "% recall" in page


def test_examples_match_what_they_show(site: Path) -> None:
    examples = _examples(site)
    severities = {slug: {f["severity"] for f in example["result"]["findings"]} for slug, example in examples.items()}
    assert "critical" in severities["triage"]
    assert "critical" in severities["review"]
    assert "critical" in severities["gitlab"]
    assert severities["hardened"] == set()
    assert examples["gitlab"]["result"]["kind"] == "GitLab CI"


def test_scanner_archive_is_complete(site: Path) -> None:
    with zipfile.ZipFile(site / "scanner.zip") as archive:
        names = set(archive.namelist())
    assert {"site_scan.py", "ci_agent_audit/rules.py", "ci_agent_audit/signatures/claude-code-action.yaml"} <= names
    assert not any("__pycache__" in name for name in names)


def test_source_files_stay_out_of_the_site(site: Path) -> None:
    assert not (site / "examples").exists()
    assert not (site / "site_scan.py").exists()


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("on: [issues\njobs: {", "valid YAML near line 2"),
        ("hello: world\n", "doesn't look like"),
        ("just text", "doesn't look like"),
    ],
)
def test_text_that_cannot_be_scanned_says_why(text: str, message: str) -> None:
    assert message in json.loads(scan_text(text))["error"]


def test_scan_text_honors_ignore_comments() -> None:
    text = """
on: [issues]
permissions:
  contents: read
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      # ci-agent-audit: ignore AIA001, AIA006
      - uses: anthropics/claude-code-action@v1.0.100
        with:
          prompt: "Triage ${{ github.event.issue.body }}"
"""
    result = json.loads(scan_text(text))
    assert result["findings"] == []
    assert result["ignored"] == 2


def test_scan_text_puts_the_worst_finding_first() -> None:
    text = """
on: [issues]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "Triage ${{ github.event.issue.body }}"
"""
    findings = json.loads(scan_text(text))["findings"]
    assert findings[0]["severity"] == "critical"
