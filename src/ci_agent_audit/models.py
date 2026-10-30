"""Data models for ci-agent-audit."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Severity levels for audit findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        ranks = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return ranks[self]

    @property
    def sarif_level(self) -> str:
        if self in (Severity.HIGH, Severity.CRITICAL):
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"


@dataclass(frozen=True)
class RuleMetadata:
    """Definition of a built-in security rule."""

    rule_id: str
    name: str
    severity: Severity
    short_description: str
    full_description: str
    remediation: str
    references: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DangerousFlagPattern:
    """A CLI flag or input argument pattern that enables unsafe agent execution."""

    pattern: str
    reason: str


@dataclass(frozen=True)
class ActionSignature:
    """Declarative signature for an AI GitHub Action or CLI tool (1 YAML file per tool)."""

    id: str
    name: str
    vendor: str
    description: str
    action_prefixes: list[str] = field(default_factory=list)
    non_agent_actions: list[str] = field(default_factory=list)
    cli_binaries: list[str] = field(default_factory=list)
    cli_packages: list[str] = field(default_factory=list)
    cli_subcommands: list[str] = field(default_factory=list)
    prompt_inputs: list[str] = field(default_factory=list)
    cli_prompt_flags: list[str] = field(default_factory=list)
    dangerous_inputs: dict[str, str] = field(default_factory=dict)
    dangerous_arg_patterns: list[DangerousFlagPattern] = field(default_factory=list)
    min_safe_version: str | None = None
    advisory_url: str | None = None
    source_file: str | None = None


@dataclass
class Finding:
    """A security issue detected in a CI/CD workflow file."""

    rule_id: str
    rule_name: str
    severity: Severity
    file_path: Path
    line: int
    column: int
    message: str
    remediation: str
    job_id: str | None = None
    step_name: str | None = None
    snippet: str | None = None
    tool_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "file": str(self.file_path.as_posix()),
            "line": self.line,
            "column": self.column,
            "job_id": self.job_id,
            "step_name": self.step_name,
            "tool_id": self.tool_id,
            "message": self.message,
            "remediation": self.remediation,
            "snippet": self.snippet,
        }
