"""Suppress accepted findings with inline comments or a config file."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
import re

import yaml

from ci_agent_audit.models import Finding

DEFAULT_CONFIG = ".ci-agent-audit.yml"
INLINE_RE = re.compile(r"#\s*ci-agent-audit:\s*ignore\s+(AIA\d{3}(?:\s*,\s*AIA\d{3})*)", re.IGNORECASE)
RULE_RE = re.compile(r"AIA\d{3}", re.IGNORECASE)


class ConfigError(ValueError):
    """Raised when a config file is invalid."""


@dataclass(frozen=True)
class IgnoreEntry:
    """One accepted finding from the config file."""

    rule: str
    path: str
    reason: str

    def matches(self, finding: Finding) -> bool:
        if finding.rule_id.upper() != self.rule:
            return False
        file_path = finding.file_path.as_posix()
        return (
            self.path == "*"
            or file_path == self.path
            or file_path.endswith(f"/{self.path}")
            or fnmatch(file_path, self.path)
            or fnmatch(file_path, f"*/{self.path}")
        )


def load_config(path: Path) -> list[IgnoreEntry]:
    """Read ignore entries, requiring a reason for each one."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"{path.as_posix()}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path.as_posix()}: The config must be a YAML mapping.")

    raw_entries = data.get("ignore") or []
    if not isinstance(raw_entries, list):
        raise ConfigError(f"{path.as_posix()}: 'ignore' must be a list.")

    entries: list[IgnoreEntry] = []
    for index, raw in enumerate(raw_entries):
        rule = str(raw.get("rule") or "").upper() if isinstance(raw, dict) else ""
        reason = str(raw.get("reason") or "").strip() if isinstance(raw, dict) else ""
        if not RULE_RE.fullmatch(rule) or not reason:
            raise ConfigError(f"{path.as_posix()}: ignore[{index}] needs a rule such as AIA006 and a reason.")
        entries.append(IgnoreEntry(rule=rule, path=str(raw.get("path") or "*"), reason=reason))
    return entries


def _inline_rules(line: str) -> set[str]:
    match = INLINE_RE.search(line)
    return {rule.upper() for rule in RULE_RE.findall(match.group(1))} if match else set()


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _step_start(lines: list[str], index: int) -> int:
    """Return the first line of the list item holding `index`, or `index` outside one."""
    indent = _indent(lines[index])
    for position in range(index, -1, -1):
        line = lines[position]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.lstrip().startswith("- ") and (position == index or _indent(line) < indent):
            return position
        indent = min(indent, _indent(line))
    return index


def _comment_block_covers(rule: str, lines: list[str], start: int) -> bool:
    above = start - 1
    while above >= 0 and lines[above].lstrip().startswith("#"):
        if rule in _inline_rules(lines[above]):
            return True
        above -= 1
    return False


def is_inline_ignored(finding: Finding, lines: list[str]) -> bool:
    """Return True if the finding's line, or a comment above it or its step, names its rule."""
    index = finding.line - 1
    if not 0 <= index < len(lines):
        return False
    rule = finding.rule_id.upper()
    return (
        rule in _inline_rules(lines[index])
        or _comment_block_covers(rule, lines, index)
        or _comment_block_covers(rule, lines, _step_start(lines, index))
    )


def filter_findings(findings: list[Finding], entries: list[IgnoreEntry]) -> tuple[list[Finding], int]:
    """Return findings still reported, plus how many were ignored."""
    lines: dict[Path, list[str]] = {}
    kept: list[Finding] = []
    for finding in findings:
        path = finding.file_path
        if path not in lines:
            lines[path] = path.read_text(encoding="utf-8").splitlines()
        if not is_inline_ignored(finding, lines[path]) and not any(entry.matches(finding) for entry in entries):
            kept.append(finding)
    return kept, len(findings) - len(kept)
