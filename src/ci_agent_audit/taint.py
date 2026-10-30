"""Taint analysis for untrusted GitHub Actions and GitLab CI event inputs."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Mapping

# GitHub Actions context expressions controlled by external / untrusted users
UNTRUSTED_GITHUB_CONTEXT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"github\.event\.issue\.(?:title|body)", re.IGNORECASE),
    re.compile(r"github\.event\.pull_request\.(?:title|body)", re.IGNORECASE),
    re.compile(r"github\.event\.pull_request\.head\.(?:ref|label)", re.IGNORECASE),
    re.compile(r"github\.event\.comment\.body", re.IGNORECASE),
    re.compile(r"github\.event\.review\.body", re.IGNORECASE),
    re.compile(r"github\.event\.review_comment\.body", re.IGNORECASE),
    re.compile(r"github\.event\.discussion\.(?:title|body)", re.IGNORECASE),
    re.compile(r"github\.event\.discussion_comment\.body", re.IGNORECASE),
    re.compile(r"github\.event\.commits(?:\[.*?\]|\.\*)\.(?:message|author\.name)", re.IGNORECASE),
    re.compile(r"github\.event\.head_commit\.(?:message|author\.name)", re.IGNORECASE),
    re.compile(r"github\.event\.pages(?:\[.*?\]|\.\*)\.page_name", re.IGNORECASE),
    re.compile(r"github\.event\.client_payload(?:\.[\w.-]+)?", re.IGNORECASE),
    re.compile(r"github\.event\.workflow_run\.(?:head_branch|display_title|head_commit\.message)", re.IGNORECASE),
    re.compile(r"github\.head_ref", re.IGNORECASE),
)

# Outputs agent actions report about the run itself, which are not model text
AGENT_METADATA_OUTPUTS = {"execution_file", "conclusion", "session_id", "branch_name", "github_token"}

# Whole event objects embed attacker-controlled fields once serialized (e.g. `toJSON(github.event.issue)`).
# Outside toJSON they render as "Object" or act as booleans, so they carry no text.
UNTRUSTED_WHOLE_OBJECT_RE = re.compile(
    r"tojson\(\s*github\.event(?:\.(?:issue|pull_request|comment|review|review_comment|discussion|"
    r"discussion_comment|head_commit|commits))?\s*\)",
    re.IGNORECASE,
)

# Event fields that stay empty unless the run was started by an issue, PR, comment, or discussion
SUBJECT_EVENT_FIELD_RE = re.compile(
    r"^(?:tojson\(\s*)?github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|"
    r"discussion_comment)\b",
    re.IGNORECASE,
)

# `gh` CLI calls whose output contains text written by issue/PR authors
GH_FETCH_RE = re.compile(
    r"\bgh\s+(?:issue|pr)\s+(?:view|diff|list)\b|\bgh\s+search\s+(?:issues|prs)\b|"
    r"\bgh\s+api\b[^\n]*\b(?:issues|pulls)\b",
    re.IGNORECASE,
)

# GitLab CI predefined variables controlled by external MR / issue authors
UNTRUSTED_GITLAB_VAR_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\$\{?CI_MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME)\}?", re.IGNORECASE),
    re.compile(r"\$\{?CI_COMMIT_(?:MESSAGE|TITLE|DESCRIPTION|REF_NAME)\}?", re.IGNORECASE),
    re.compile(r"\$\{?CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME\}?", re.IGNORECASE),
)

GHA_EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
OUTPUT_REF_RE = re.compile(r"\b(?:steps|needs)\.[\w-]+\.outputs\.[\w-]+", re.IGNORECASE)
SHELL_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_]\w*)=")
REDIRECT_RE = re.compile(r">>\s*[\"']?\$\{?GITHUB_(ENV|OUTPUT)\}?[\"']?")
GROUP_REDIRECT_RE = re.compile(r"^\s*\}\s*>>\s*[\"']?\$\{?GITHUB_(ENV|OUTPUT)\}?[\"']?")
FILE_WRITE_RE = re.compile(r"(?<![\d&>])>{1,2}\s*[\"']?(\$\{?\w+\}?|[\w./-]*[A-Za-z][\w./-]*)")
LITERAL_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_]\w*)=[\"']?([\w./-]+)[\"']?\s*$")
SET_OUTPUT_RE = re.compile(r"core\.setOutput\(\s*['\"]([\w-]+)['\"]\s*,\s*([^\n]*)\)")
STEP_OUTPUT_RE = re.compile(r"\bsteps\.([\w-]+)\.outputs\.([\w-]+)", re.IGNORECASE)
FILE_HEREDOC_RE = re.compile(r"^\s*cat\s+<<-?\s*[\"']?(\w+)[\"']?\s*>\s*[\"']?([^\s\"'>]+)")
USER_TEXT_FIELD_RE = re.compile(r"\b(?:body|title|comments)\b")
EXPORT_LINE_RE = re.compile(r"(?:echo|printf)\s+(?:-\S+\s+)*[\"']?([A-Za-z_][\w-]*)(=|<<)([\"']?)(\w*)")


def find_direct_untrusted_sources(value: str) -> list[str]:
    """Return all untrusted GitHub/GitLab expressions directly referenced in `value`."""
    if not value or not isinstance(value, str):
        return []

    matches: list[str] = []
    # Check GitHub ${{ ... }} blocks
    for expr_match in GHA_EXPRESSION_RE.finditer(value):
        inner = expr_match.group(1)
        for pat in (*UNTRUSTED_GITHUB_CONTEXT_PATTERNS, UNTRUSTED_WHOLE_OBJECT_RE):
            for found in pat.finditer(inner):
                token = found.group(0)
                if token not in matches:
                    matches.append(token)

    # Also check raw expressions (e.g. inside `if:` or GitLab variables)
    for pat in UNTRUSTED_GITHUB_CONTEXT_PATTERNS:
        for found in pat.finditer(value):
            token = found.group(0)
            if token not in matches:
                matches.append(token)

    for pat in UNTRUSTED_GITLAB_VAR_PATTERNS:
        for found in pat.finditer(value):
            token = found.group(0)
            if token not in matches:
                matches.append(token)

    return matches


def collect_tainted_env_map(
    *env_blocks: Mapping[str, object] | None,
    base: Mapping[str, list[str]] | None = None,
    tainted_refs: Mapping[str, list[str]] | None = None,
) -> dict[str, list[str]]:
    """Build a map of `ENV_VAR_NAME -> [untrusted_source_expressions]` across workflow/job/step scopes."""
    tainted: dict[str, list[str]] = dict(base or {})
    for block in env_blocks:
        if not isinstance(block, Mapping):
            continue
        for key, raw_val in block.items():
            if raw_val is None:
                continue
            val_str = str(raw_val)
            direct = find_direct_untrusted_sources(val_str) + _ref_sources(val_str, tainted_refs)
            if direct:
                tainted[str(key)] = direct
            else:
                # Check if this env var references an already-tainted env var
                inherited: list[str] = []
                for prev_key, prev_sources in tainted.items():
                    if prev_key != str(key) and references_env_var(val_str, prev_key):
                        for src in prev_sources:
                            if src not in inherited:
                                inherited.append(src)
                if inherited:
                    tainted[str(key)] = inherited
                else:
                    # A clean value in an inner scope shadows a tainted outer one
                    tainted.pop(str(key), None)
    return tainted


def _ref_sources(value: str, tainted_refs: Mapping[str, list[str]] | None) -> list[str]:
    """Return untrusted sources reachable through `steps.*.outputs.*` / `needs.*.outputs.*` references."""
    if not tainted_refs:
        return []
    sources: list[str] = []
    for ref in OUTPUT_REF_RE.findall(value):
        for src in tainted_refs.get(ref.lower(), []):
            label = f"{src} (via {ref})"
            if label not in sources:
                sources.append(label)
    return sources


def references_env_var(text: str, env_name: str) -> bool:
    """Return True if `text` references `env_name` via `$VAR`, `${VAR}`, or `${{ env.VAR }}`."""
    escaped = re.escape(env_name)
    patterns = (
        rf"\$\{{\{{\s*env\.{escaped}\b.*?\}}\}}",
        rf"\$\{{{escaped}(?::[-+?][^}}]*)?\}}",
        rf"\${escaped}\b",
        rf"%{{?{escaped}}}?%",
    )
    return any(re.search(p, text) for p in patterns)


def find_all_taint_sources(
    value: str,
    tainted_env: Mapping[str, list[str]] | None = None,
    tainted_refs: Mapping[str, list[str]] | None = None,
    *,
    include_events: bool = True,
) -> list[str]:
    """Return direct untrusted sources plus any sources propagated via `env:` or step/job outputs."""
    if not value or not isinstance(value, str):
        return []

    sources = find_direct_untrusted_sources(value) if include_events else []
    if tainted_env:
        for env_name, env_sources in tainted_env.items():
            if references_env_var(value, env_name):
                for src in env_sources:
                    label = f"{src} (via env.{env_name})"
                    if label not in sources and src not in sources:
                        sources.append(label)
    for label in _ref_sources(value, tainted_refs):
        if label not in sources:
            sources.append(label)
    return sources


def _reads_untrusted_text(line: str) -> str | None:
    """Return a label if a shell line pulls text written by issue or PR authors."""
    if GH_FETCH_RE.search(line):
        # `--json number` returns only trusted fields
        if "--json" not in line or USER_TEXT_FIELD_RE.search(line):
            return "gh CLI output"
    if "GITHUB_EVENT_PATH" in line and USER_TEXT_FIELD_RE.search(line):
        return "event payload"
    return None


def _group_redirect_targets(lines: list[str]) -> dict[int, str]:
    """Map line indexes inside `{ ...; } >> "$GITHUB_OUTPUT"` groups to their redirect target."""
    targets: dict[int, str] = {}
    open_lines: list[int] = []
    for idx, line in enumerate(lines):
        if line.strip() == "{":
            open_lines.append(idx)
            continue
        closing = GROUP_REDIRECT_RE.match(line)
        if closing and open_lines:
            for inner in range(open_lines.pop(), idx):
                targets[inner] = closing.group(1).upper()
    return targets


@dataclass
class TaintState:
    """Untrusted data known to a job: env vars plus step/job outputs seen so far."""

    env: dict[str, list[str]] = field(default_factory=dict)
    refs: dict[str, list[str]] = field(default_factory=dict)
    files: dict[str, list[str]] = field(default_factory=dict)
    subject_fields_empty: bool = False
    agent_steps: set[str] = field(default_factory=set)
    # Tracks model text alone, so event data and `gh` output are not mistaken for it
    agent_only: bool = False

    def scoped(self, step_env: Mapping[str, object] | None) -> dict[str, list[str]]:
        """Return the tainted env map as seen by a step with its own `env:` block."""
        if not self.agent_only:
            return collect_tainted_env_map(step_env, base=self.env, tainted_refs=self.refs)
        env = dict(self.env)
        for key, value in (step_env or {}).items():
            sources = self.sources(str(value or ""), env)
            if sources:
                env[str(key)] = sources
            else:
                env.pop(str(key), None)
        return env

    def _agent_sources(self, value: str) -> list[str]:
        return [
            f"agent output (steps.{step_id}.outputs.{output})"
            for step_id, output in STEP_OUTPUT_RE.findall(value)
            if step_id.lower() in self.agent_steps and output.lower() not in AGENT_METADATA_OUTPUTS
        ]

    def sources(self, value: str, tainted_env: Mapping[str, list[str]]) -> list[str]:
        found = find_all_taint_sources(value, tainted_env, self.refs, include_events=not self.agent_only)
        for name, file_sources in self.files.items():
            if re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w-])", value):
                found.extend(f"{src} (via file {name})" for src in file_sources)
        found.extend(self._agent_sources(value))
        if self.subject_fields_empty:
            found = [src for src in found if not SUBJECT_EVENT_FIELD_RE.match(src)]
        return found

    def absorb_github_script(self, step_id: str, script: str) -> None:
        """Record `core.setOutput` calls that pass on issue or PR text."""
        if not step_id:
            return
        for name, value in SET_OUTPUT_RE.findall(script):
            if USER_TEXT_FIELD_RE.search(value):
                self.refs[f"steps.{step_id}.outputs.{name}".lower()] = ["github-script issue data"]

    def _export(self, target: str, step_id: str, name: str, sources: list[str]) -> None:
        if not sources:
            return
        if target == "ENV":
            self.env[name] = sources
        elif step_id:
            self.refs[f"steps.{step_id}.outputs.{name}".lower()] = sources

    def absorb_step(self, step_id: str, run: str, step_env: Mapping[str, object] | None = None) -> None:
        """Record what a `run:` step writes to `$GITHUB_ENV` / `$GITHUB_OUTPUT`."""
        local = self.scoped(step_env)
        literals: dict[str, str] = {}
        lines = run.replace("\\\n", " ").splitlines()
        group_targets = _group_redirect_targets(lines)
        heredoc: tuple[str, str, str] | None = None
        file_heredoc: tuple[str, str] | None = None

        for idx, line in enumerate(lines):
            sources = self.sources(line, local)
            fetched = None if self.agent_only else _reads_untrusted_text(line)
            if fetched:
                sources = [*sources, fetched]

            if file_heredoc is not None:
                delimiter, name = file_heredoc
                if line.strip() == delimiter:
                    file_heredoc = None
                elif sources:
                    self.files[name.rsplit("/", 1)[-1]] = sources
                continue
            opened_file = FILE_HEREDOC_RE.search(line)
            if opened_file:
                file_heredoc = (opened_file.group(1), opened_file.group(2))
                continue

            if heredoc is not None:
                target, name, delimiter = heredoc
                if re.search(rf"(?<!\w){re.escape(delimiter)}(?!\w)", line):
                    heredoc = None
                else:
                    self._export(target, step_id, name, sources)
                continue

            literal = LITERAL_ASSIGN_RE.match(line)
            if literal:
                literals[literal.group(1)] = literal.group(2)

            assignment = SHELL_ASSIGN_RE.match(line)
            if assignment:
                if sources:
                    local[assignment.group(1)] = sources
                else:
                    local.pop(assignment.group(1), None)

            redirect = REDIRECT_RE.search(line)
            target = redirect.group(1).upper() if redirect else group_targets.get(idx)
            export = EXPORT_LINE_RE.search(line) if target else None
            if target and export:
                if export.group(2) == "<<":
                    heredoc = (target, export.group(1), export.group(4) or "EOF")
                else:
                    self._export(target, step_id, export.group(1), sources)
            elif sources and not target:
                self._record_file(FILE_WRITE_RE.search(line), literals, sources)

    def _record_file(self, write: re.Match[str] | None, literals: Mapping[str, str], sources: list[str]) -> None:
        if write is None:
            return
        path = write.group(1)
        if path.startswith("$"):
            path = literals.get(path.strip("${}"), "")
        if path and not path.startswith("/dev/"):
            self.files[path.rsplit("/", 1)[-1]] = sources
