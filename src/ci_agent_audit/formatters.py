"""Output formatters for ci-agent-audit (text, json, sarif, github)."""

from __future__ import annotations

import json
from typing import Iterable

from ci_agent_audit import __version__
from ci_agent_audit.models import Finding, Severity
from ci_agent_audit.rules import RULES_CATALOG


def format_text(findings: Iterable[Finding]) -> str:
    """Format findings as human-readable terminal report."""
    items = list(findings)
    if not items:
        return "✓ ci-agent-audit: 0 security issues found in scanned CI/CD workflows."

    lines: list[str] = []
    for f in items:
        sev_badge = f"[{f.severity.value.upper()}]"
        loc = f"{f.file_path.as_posix()}:{f.line}:{f.column}"
        context = f" (job: {f.job_id})" if f.job_id else ""
        lines.append(f"{sev_badge} {f.rule_id} ({f.rule_name}) at {loc}{context}")
        lines.append(f"  Message:     {f.message}")
        if f.snippet:
            lines.append(f"  Snippet:     {f.snippet}")
        lines.append(f"  Remediation: {f.remediation}")
        lines.append("")

    counts = {s: 0 for s in Severity}
    for f in items:
        counts[f.severity] += 1

    summary_parts = [
        f"{counts[Severity.CRITICAL]} critical",
        f"{counts[Severity.HIGH]} high",
        f"{counts[Severity.MEDIUM]} medium",
        f"{counts[Severity.LOW]} low",
    ]
    lines.append(
        f"✗ ci-agent-audit: Found {len(items)} issue(s) ({', '.join(summary_parts)})."
    )
    return "\n".join(lines)


def format_json(findings: Iterable[Finding]) -> str:
    """Format findings as structured JSON."""
    items = [f.to_dict() for f in findings]
    payload = {
        "tool": "ci-agent-audit",
        "version": __version__,
        "total_findings": len(items),
        "findings": items,
    }
    return json.dumps(payload, indent=2)


def format_github_annotations(findings: Iterable[Finding]) -> str:
    """Format findings as GitHub Actions workflow commands (`::error`, `::warning`, `::notice`)."""
    lines: list[str] = []
    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            level = "error"
        elif f.severity == Severity.MEDIUM:
            level = "warning"
        else:
            level = "notice"

        title = f"{f.rule_id} ({f.rule_name})"
        escaped_msg = f.message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        file_str = f.file_path.as_posix()
        lines.append(
            f"::{level} file={file_str},line={f.line},col={f.column},title={title}::{escaped_msg}"
        )
    return "\n".join(lines)


def format_sarif(findings: Iterable[Finding]) -> str:
    """Format findings as SARIF v2.1.0 for GitHub Code Scanning / Security tab."""
    items = list(findings)
    rules_list = []
    for rule_id, meta in sorted(RULES_CATALOG.items()):
        rules_list.append(
            {
                "id": rule_id,
                "name": meta.name,
                "shortDescription": {"text": meta.short_description},
                "fullDescription": {"text": meta.full_description},
                "help": {
                    "text": f"{meta.full_description}\n\nRemediation: {meta.remediation}",
                },
                "defaultConfiguration": {"level": meta.severity.sarif_level},
                "properties": {
                    "tags": ["security", "ci-cd", "ai-agents", "prompt-injection"],
                    "security-severity": _sarif_security_score(meta.severity),
                },
            }
        )

    results = []
    for f in items:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level,
                "message": {"text": f"{f.message} Remediation: {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path.as_posix()},
                            "region": {
                                "startLine": max(1, f.line),
                                "startColumn": max(1, f.column),
                            },
                        }
                    }
                ],
            }
        )

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ci-agent-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/layer8labs8/ci-agent-audit",
                        "rules": rules_list,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def _sarif_security_score(severity: Severity) -> str:
    scores = {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "7.8",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "3.0",
    }
    return scores[severity]
