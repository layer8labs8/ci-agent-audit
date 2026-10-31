"""Scan pasted workflow text, in the site build and in the browser."""

from __future__ import annotations

import json
from pathlib import Path
import re
import tempfile

import yaml

from ci_agent_audit.models import Severity
from ci_agent_audit.rules import scan_workflow_file
from ci_agent_audit.suppress import filter_findings
from ci_agent_audit.yaml_loader import load_yaml_with_lines


def _kind(root: object) -> str | None:
    if not isinstance(root, dict):
        return None
    if isinstance(root.get("jobs"), dict):
        return "GitHub Actions"
    if any(isinstance(job, dict) and "script" in job for job in root.values()):
        return "GitLab CI"
    return None


def scan_text(text: str) -> str:
    """Return the scan of one workflow as JSON for the page."""
    try:
        root, lines = load_yaml_with_lines(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" near line {mark.line + 1}" if mark else ""
        return json.dumps({"error": f"This isn't valid YAML{where}."})

    kind = _kind(root)
    if kind is None:
        return json.dumps({"error": "This doesn't look like a GitHub Actions or GitLab CI file."})

    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "workflow.yml"
        path.write_text(text, encoding="utf-8")
        findings, ignored = filter_findings(scan_workflow_file(path), [])

    findings.sort(key=lambda finding: (-Severity(finding.severity).rank, finding.line))
    local_calls = any(re.match(r"\s*(?:- )?uses:\s*[\"']?\./", line) for line in lines)
    return json.dumps(
        {
            "kind": kind,
            "ignored": ignored,
            "local_calls": local_calls,
            "findings": [finding.to_dict() for finding in findings],
        }
    )
