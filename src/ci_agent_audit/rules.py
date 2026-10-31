"""Security audit rules (AIA001 - AIA011) and workflow scanner engine."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Mapping

from ci_agent_audit.models import ActionSignature, Finding, RuleMetadata, Severity
from ci_agent_audit.signatures_loader import load_signatures
from ci_agent_audit.taint import (
    GH_FETCH_RE,
    GHA_EXPRESSION_RE,
    TaintState,
    collect_tainted_env_map,
    find_all_taint_sources,
    references_env_var,
)
from ci_agent_audit.yaml_loader import LineDict, load_workflow_file

RULES_CATALOG: dict[str, RuleMetadata] = {
    "AIA001": RuleMetadata(
        rule_id="AIA001",
        name="promptpwnd-untrusted-input",
        severity=Severity.CRITICAL,
        short_description="Untrusted CI event input flows into an AI agent prompt sink (PromptPwnd).",
        full_description=(
            "Passing untrusted user input (such as github.event.issue.body, pull_request.body, "
            "or comment.body) directly or via environment variables into an AI agent prompt allows "
            "attackers to perform indirect prompt injection (PromptPwnd), hijacking agent tools and secrets."
        ),
        remediation=(
            "Do not interpolate untrusted event bodies directly into AI prompt arguments. "
            "Restrict workflow execution to trusted collaborators (e.g., author_association checks), "
            "strip/sanitize untrusted inputs, and disable shell/write tools when processing public issues."
        ),
        references=[
            "https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents",
            "https://github.com/anthropics/claude-code-action/releases/tag/v1.0.94",
        ],
    ),
    "AIA002": RuleMetadata(
        rule_id="AIA002",
        name="dangerous-agent-permissions",
        severity=Severity.HIGH,
        short_description="AI coding agent invoked with dangerous permission-bypass or auto-execution flags.",
        full_description=(
            "Flags such as --dangerously-skip-permissions, --yolo, --dangerously-auto-approve-everything, "
            "or unrestricted Bash(*) tool access allow an AI agent in CI to execute arbitrary host commands."
        ),
        remediation=(
            "Remove full permission-bypass flags in CI. Explicitly allowlist only the minimum required "
            "read-only tools (e.g., --allowedTools 'Read,Grep,Glob') or isolate execution inside a firewalled container."
        ),
        references=[
            "https://docs.anthropic.com/en/docs/claude-code/security",
        ],
    ),
    "AIA003": RuleMetadata(
        rule_id="AIA003",
        name="spoofable-bot-actor-check",
        severity=Severity.CRITICAL,
        short_description="Spoofable [bot] actor condition or wildcard non-write user access on AI workflow.",
        full_description=(
            "Trusting any GitHub actor ending in '[bot]' or setting allowed_non_write_users: '*' allows "
            "external attackers to register a GitHub App or trigger the AI agent from an untrusted account "
            "(the exact vector behind the CVSS 7.8 claude-code-action bypass)."
        ),
        remediation=(
            "Never use endsWith(github.actor, '[bot]') or allowed_non_write_users: '*' to authorize AI agents. "
            "Explicitly allowlist exact trusted bot usernames (e.g., github.actor == 'dependabot[bot]') and "
            "require write/maintainer permissions."
        ),
        references=[
            "https://github.com/anthropics/claude-code-action/releases/tag/v1.0.94",
            "https://thehackernews.com/2026/06/claude-code-github-action-flaw-let-one.html",
        ],
    ),
    "AIA004": RuleMetadata(
        rule_id="AIA004",
        name="vulnerable-ai-action-version",
        severity=Severity.HIGH,
        short_description="AI GitHub Action is pinned to a vulnerable version or mutable branch ref.",
        full_description=(
            "Using an older version of an AI GitHub Action with known permission/injection vulnerabilities "
            "(such as anthropics/claude-code-action prior to v1.0.94) or pinning to a mutable branch (@main/@master) "
            "exposes the pipeline to supply-chain and prompt-injection exploits."
        ),
        remediation=(
            "Upgrade the tool to its latest safe release and pin it to an immutable "
            "full-length commit SHA or verified release tag."
        ),
        references=[
            "https://github.com/anthropics/claude-code-action/releases/tag/v1.0.94",
        ],
    ),
    "AIA005": RuleMetadata(
        rule_id="AIA005",
        name="overprivileged-ai-token",
        severity=Severity.HIGH,
        short_description="AI agent job runs with write-scoped or unrestricted default GITHUB_TOKEN permissions.",
        full_description=(
            "When an AI agent runs in a workflow without an explicit least-privilege 'permissions:' block "
            "or with 'write-all' / 'contents: write' on untrusted triggers (issues, issue_comment, pull_request_target), "
            "a prompt injection can push commits, create releases, or exfiltrate repository secrets."
        ),
        remediation=(
            "Add an explicit least-privilege 'permissions:' block at the workflow or job level "
            "(e.g., 'contents: read', 'pull-requests: write' only if commenting is required)."
        ),
        references=[
            "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication",
        ],
    ),
    "AIA006": RuleMetadata(
        rule_id="AIA006",
        name="missing-egress-firewall",
        severity=Severity.MEDIUM,
        short_description="AI agent job runs without a network egress firewall (e.g., step-security/harden-runner).",
        full_description=(
            "Autonomous coding agents in CI have access to API keys (ANTHROPIC_API_KEY, GEMINI_API_KEY, GITHUB_TOKEN) "
            "and shell tools. Without an outbound network egress allowlist, a prompt-injected agent can exfiltrate "
            "secrets to an attacker-controlled server via curl/wget/DNS."
        ),
        remediation=(
            "Add 'step-security/harden-runner' with 'egress-policy: block' (allowlisting only the LLM API and github.com) "
            "as the first step of the AI job, or use a firewall-enabled runner image (e.g., ubuntu-24.04-firewall)."
        ),
        references=[
            "https://github.com/step-security/harden-runner",
        ],
    ),
    "AIA007": RuleMetadata(
        rule_id="AIA007",
        name="unpinned-mcp-server-in-ci",
        severity=Severity.HIGH,
        short_description="Unpinned Model Context Protocol (MCP) server dynamically executed in CI via npx/uvx.",
        full_description=(
            "Launching MCP servers inside CI workflows using 'npx -y @scope/pkg' or 'uvx pkg' without an exact "
            "version pin exposes the AI agent's environment and secrets to registry compromises and slopsquatting."
        ),
        remediation=(
            "Pin every MCP server package executed via npx, uvx, or pipx in CI to an exact immutable version "
            "(e.g., 'npx --yes @modelcontextprotocol/server-github@2026.4.1') or pre-install from a locked manifest."
        ),
        references=[
            "https://modelcontextprotocol.io/specification",
        ],
    ),
    "AIA008": RuleMetadata(
        rule_id="AIA008",
        name="ai-pull-request-target-checkout",
        severity=Severity.CRITICAL,
        short_description="Workflow triggered by pull_request_target checks out untrusted PR code and runs an AI agent.",
        full_description=(
            "Combining 'pull_request_target' (which grants access to base repository secrets and a privileged token) "
            "with a checkout of the untrusted PR head ref and an AI coding agent allows attacker-modified CLAUDE.md, "
            "hooks, .mcp.json, or source files to execute arbitrary code and steal repository secrets."
        ),
        remediation=(
            "Do not check out untrusted PR head refs inside 'pull_request_target' jobs that run AI agents. "
            "Use 'pull_request' with read-only permissions, or pass only sanitized diff metadata without checking out PR code."
        ),
        references=[
            "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        ],
    ),
    "AIA009": RuleMetadata(
        rule_id="AIA009",
        name="agent-fetches-untrusted-context",
        severity=Severity.HIGH,
        short_description="AI agent on an externally reachable trigger reads issue or PR text through the gh CLI.",
        full_description=(
            "The prompt itself can look clean while the agent is told, or allowed, to run `gh issue view` or "
            "`gh pr view`. The text it reads is written by the attacker, so this is indirect prompt injection "
            "that no `${{ }}` expression reveals."
        ),
        remediation=(
            "Gate the job on `author_association` or an explicit maintainer check, remove `gh` from the agent's "
            "allowed tools on public triggers, or run the agent with read-only tools and no secrets."
        ),
        references=[
            "https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents",
        ],
    ),
    "AIA010": RuleMetadata(
        rule_id="AIA010",
        name="agent-output-to-execution",
        severity=Severity.CRITICAL,
        short_description="AI agent output reaches a shell, git command, or checkout target.",
        full_description=(
            "Model output is attacker-influenced whenever the model reads outside text. Interpolating it into "
            "a `run:` block, passing it to `eval`, or letting it pick a git ref turns a prompt injection into "
            "command execution or a checkout of attacker-chosen code."
        ),
        remediation=(
            "Pass agent output through `env:` and treat it as data. Validate it against a fixed allowlist "
            "before using it as a command, branch, ref, or path."
        ),
        references=[
            "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions",
        ],
    ),
    "AIA011": RuleMetadata(
        rule_id="AIA011",
        name="agent-pushes-default-branch",
        severity=Severity.HIGH,
        short_description="Job pushes to the default branch after an AI agent ran, with no human review.",
        full_description=(
            "When a job runs an agent and then pushes straight to `main` or `master`, a prompt injection lands "
            "in the default branch without any pull request or review."
        ),
        remediation=(
            "Push the agent's work to a separate branch and open a pull request, and protect the default branch."
        ),
        references=[
            "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches",
        ],
    ),
}

UNTRUSTED_TRIGGERS = {
    "issues",
    "issue_comment",
    "pull_request",
    "pull_request_target",
    "pull_request_review",
    "pull_request_review_comment",
    "discussion",
    "discussion_comment",
}

# Fork `pull_request` runs get no secrets, so reading PR text there is not privileged
PRIVILEGED_UNTRUSTED_TRIGGERS = (UNTRUSTED_TRIGGERS - {"pull_request"}) | {"workflow_run"}

# Scheduled runs hold secrets and can read whatever text outsiders have filed
FETCH_RISK_TRIGGERS = PRIVILEGED_UNTRUSTED_TRIGGERS | {"schedule"}

# These runs carry no issue or PR in their event payload
NO_SUBJECT_TRIGGERS = {"schedule", "workflow_dispatch", "push"}

# Reusable workflows are usually gated by their caller, which a single file cannot show
CALLER_GATED_TRIGGERS = {"workflow_call", "workflow_dispatch"}

GH_TOOL_GRANT_RE = re.compile(r"Bash\(gh[\s:*)]")

# Ways a CLI is started besides its bare name: wrappers, env prefixes, and package runners
# Triggers where model output can be steered by someone outside the project
OUTPUT_RISK_TRIGGERS = UNTRUSTED_TRIGGERS | FETCH_RISK_TRIGGERS

# Conditions that limit who can start a run. `!=` checks and `[bot]` suffixes are deliberately absent.
ACTOR_GUARD_RE = re.compile(
    r"author_association|"
    r"github\.(?:actor|triggering_actor)\s*==|==\s*github\.(?:actor|triggering_actor)\b|"
    r"(?<!!)contains\(\s*fromjson\(.*?\)\s*,\s*github\.(?:actor|triggering_actor)\s*\)|"
    r"head\.repo\.full_name\s*==\s*github\.repository|"
    r"github\.event\.label\.name\s*==",  # Applying a label needs triage access
    re.IGNORECASE,
)

EVAL_LINE_RE = re.compile(r"\beval\b|\b(?:ba)?sh\s+-c\b|\bpython3?\s+-c\b|\bnode\s+-e\b|\|\s*(?:ba)?sh\b")
FILE_EXEC_RE = r"(?:\b(?:ba)?sh|\bsource|\bpython3?|\bnode|(?:^|[;&|])\s*\.)\s+\S*"
PR_CHECKOUT_COMMAND_RE = re.compile(r"\bgh\s+pr\s+checkout\b|\bgit\s+fetch\b[^\n]*\bpull/")
GIT_TARGET_LINE_RE = re.compile(r"\bgit\s+(?:checkout|switch|branch|push|reset|clone)\b")
DEFAULT_BRANCH_PUSH_RE = re.compile(
    r"\bgit\s+push\b(?![^\n]*--dry-run)[^\n;&|]*?\s(?:HEAD:)?(?:refs/heads/)?(?:main|master)(?=\s|$|[;&|])",
    re.MULTILINE,
)

CLI_PREFIX = (
    r"(?:^|[;&|(]\s*|\$\(\s*)[ \t]*"
    r"(?:(?:sudo|nohup|time|exec|command|xvfb-run|timeout\s+\S+|env|[A-Za-z_]\w*=\S*)\s+)*"
)
CLI_RUNNER = r"(?:npx|bunx|uvx|pipx\s+run|pnpm\s+dlx|yarn\s+dlx)(?:\s+-{1,2}\S+)*\s+"
CLI_INFO_ONLY = r"(?!\s+(?:--version|-v|--help|-h)\s*(?:$|[;&|)]))"

SPOOFABLE_BOT_RE = re.compile(
    r"(?<![!\w])(?:endsWith|contains)\s*\(\s*github\.(?:actor|triggering_actor|event\.sender\.login)\s*,\s*['\"]\[bot\]['\"]\s*\)",
    re.IGNORECASE,
)

UNPINNED_MCP_RE = re.compile(
    r"(?:npx\s+(?:--yes\s+|-y\s+)*|uvx\s+|pipx\s+run\s+)(?P<pkg>(?:@[a-zA-Z0-9._-]+/)?[a-zA-Z0-9._-]+)(?P<ver>@[a-zA-Z0-9._-]+)?",
    re.IGNORECASE,
)


def _iter_unpinned_mcp_packages(text: str) -> list[str]:
    """Return MCP package names invoked via npx/uvx/pipx without a pinned version."""
    unpinned: list[str] = []
    for m in UNPINNED_MCP_RE.finditer(text):
        pkg = m.group("pkg")
        ver = m.group("ver")
        pkg_lower = pkg.lower()
        if "mcp" not in pkg_lower and "modelcontextprotocol" not in pkg_lower:
            continue
        if not ver or ver.lower() in {"@latest", "@main", "@master", "@next"}:
            unpinned.append(pkg)
    return unpinned

PR_HEAD_CHECKOUT_RE = re.compile(
    r"github\.event\.pull_request\.(?:head\.(?:sha|ref)|merge_commit_sha)|github\.head_ref|refs/pull/",
    re.IGNORECASE,
)


def _parse_semver_tuple(version_str: str) -> tuple[int, ...] | None:
    cleaned = version_str.strip().lstrip("vV")
    if not re.match(r"^\d+\.\d+\.\d+$", cleaned):
        return None
    return tuple(int(p) for p in cleaned.split("."))


def _get_snippet(lines: list[str], line_num: int) -> str | None:
    if 1 <= line_num <= len(lines):
        return lines[line_num - 1].strip()
    return None


def _extract_triggers(root: LineDict) -> set[str]:
    on_block = root.get("on")
    if isinstance(on_block, str):
        return {on_block}
    if isinstance(on_block, list):
        return {str(x) for x in on_block}
    if isinstance(on_block, Mapping):
        return {str(k) for k in on_block.keys()}
    return set()


def _match_action_signature(
    uses_value: str,
    signatures: list[ActionSignature],
) -> tuple[ActionSignature | None, str | None]:
    """Return (matched_signature, version_ref) if `uses:` matches a known AI GitHub Action."""
    if "@" in uses_value:
        action_slug, version_ref = uses_value.split("@", 1)
    else:
        action_slug, version_ref = uses_value, None

    action_slug_lower = action_slug.strip().lower()
    for sig in signatures:
        if action_slug_lower in {a.lower() for a in sig.non_agent_actions}:
            continue
        for prefix in sig.action_prefixes:
            if action_slug_lower == prefix.lower() or action_slug_lower.startswith(prefix.lower() + "/"):
                return sig, version_ref
    return None, version_ref


def _match_cli_signatures(
    run_script: str,
    signatures: list[ActionSignature],
) -> list[ActionSignature]:
    """Return all AI CLI signatures invoked inside a `run:` shell script."""
    matched: list[ActionSignature] = []
    for sig in signatures:
        subcommand = rf"\s+(?:{'|'.join(map(re.escape, sig.cli_subcommands))})\b" if sig.cli_subcommands else ""
        patterns = [
            rf"{CLI_PREFIX}(?:{CLI_RUNNER})?(?:[\w./~-]*/)?{re.escape(binary)}(?![\w.-]){subcommand}{CLI_INFO_ONLY}"
            for binary in sig.cli_binaries
        ]
        patterns += [
            rf"{CLI_PREFIX}{CLI_RUNNER}{re.escape(package)}(?:@[\w.-]+)?(?![\w./-]){CLI_INFO_ONLY}"
            for package in sig.cli_packages
        ]
        if any(re.search(pattern, run_script, re.MULTILINE) for pattern in patterns):
            matched.append(sig)
    return matched


def _absorb_step(state: TaintState, step: LineDict) -> None:
    """Record the untrusted data a step leaves behind for later steps."""
    step_id = str(step.get("id") or "")
    if step.get("run"):
        step_env = step.get("env") if isinstance(step.get("env"), Mapping) else None
        state.absorb_step(step_id, str(step["run"]), step_env)
    if "actions/github-script" in str(step.get("uses") or "").lower():
        with_block = step.get("with")
        if isinstance(with_block, Mapping) and with_block.get("script"):
            state.absorb_github_script(step_id, str(with_block["script"]))


def _guard_strength(*conditions: str) -> str | None:
    """Return "full" for a guard on every path through an `if:`, "partial" if `||` may skip it."""
    strength = None
    for condition in conditions:
        if ACTOR_GUARD_RE.search(condition):
            if all(ACTOR_GUARD_RE.search(branch) for branch in condition.split("||")):
                return "full"
            strength = "partial"
    return strength


def _is_read_only_token(perms: Any) -> bool:
    """Return True if an explicit permissions block grants no write scope."""
    if isinstance(perms, str):
        return perms.strip().lower() == "read-all"
    if isinstance(perms, Mapping):
        return not any(str(value).strip().lower() == "write" for value in perms.values())
    return False


def _agent_output_sinks(
    run: str,
    uses: str,
    with_block: Mapping[str, Any],
    step_env: Mapping[str, Any] | None,
    model_state: TaintState,
) -> list[tuple[Severity, str]]:
    """Return (severity, description) for each place a step executes or trusts model text."""
    sinks: list[tuple[Severity, str]] = []
    model_env = model_state.scoped(step_env)
    if any(model_state.sources(expr, model_env) for expr in GHA_EXPRESSION_RE.findall(run)):
        sinks.append((Severity.CRITICAL, "is interpolated into a `run:` block"))

    for name in model_env:
        lines = [line for line in run.splitlines() if references_env_var(line, name)]
        if any(EVAL_LINE_RE.search(line) for line in lines):
            sinks.append((Severity.CRITICAL, f"is executed through `env.{name}`"))
        elif any(GIT_TARGET_LINE_RE.search(line) for line in lines):
            sinks.append((Severity.HIGH, f"chooses a git target through `env.{name}`"))

    for name in model_state.files:
        if re.search(FILE_EXEC_RE + re.escape(name) + r"(?![\w-])", run, re.MULTILINE):
            sinks.append((Severity.CRITICAL, f"is executed from the file `{name}`"))

    if "actions/github-script" in uses.lower():
        if model_state.sources(str(with_block.get("script") or ""), model_env):
            sinks.append((Severity.CRITICAL, "is interpolated into `actions/github-script` code"))

    if "actions/checkout" in uses.lower():
        for key in ("ref", "repository", "path"):
            if model_state.sources(str(with_block.get(key) or ""), model_env):
                sinks.append((Severity.HIGH, f"chooses the `{key}` of actions/checkout"))
    return sinks


def _agent_lacks_shell(with_block: Mapping[str, Any]) -> bool:
    """Return True if an action's arguments leave its agent without shell access."""
    args = str(with_block.get("claude_args") or "")
    if re.search(r"--disallowed-?tools\b[^\n]*\bBash\b", args, re.IGNORECASE):
        return True
    allowlist = re.search(r"--allowed-?tools\b([^\n]*)", args, re.IGNORECASE)
    return bool(allowlist) and "Bash" not in allowlist.group(1)


def _has_cleared_token(step_env: Mapping[str, Any] | None) -> bool:
    """Return True if a step explicitly blanks the GitHub token for its agent."""
    if not step_env:
        return False
    return any(key in step_env and not str(step_env[key] or "").strip() for key in ("GITHUB_TOKEN", "GH_TOKEN"))


def _is_agent_step(step: LineDict, signatures: list[ActionSignature]) -> bool:
    uses = str(step.get("uses") or "")
    if uses and _match_action_signature(uses, signatures)[0] is not None:
        return True
    return bool(step.get("run")) and bool(_match_cli_signatures(str(step["run"]), signatures))


def _collect_job_output_taint(
    jobs: Mapping[str, Any],
    workflow_env: Mapping[str, Any] | None,
    subject_fields_empty: bool,
    signatures: list[ActionSignature] | None = None,
) -> dict[str, list[str]]:
    """Map tainted `needs.<job>.outputs.<name>` references, following chains between jobs.

    With `signatures`, the taint source is model text from agent steps instead of event data.
    """
    tainted: dict[str, list[str]] = {}
    # Each pass can only extend a chain by one job, regardless of file order
    for _ in range(len(jobs)):
        before = len(tainted)
        for job_id, job_data in jobs.items():
            if not isinstance(job_data, LineDict):
                continue
            job_env = job_data.get("env") if isinstance(job_data.get("env"), Mapping) else None
            model_only = signatures is not None
            state = TaintState(
                env={} if model_only else collect_tainted_env_map(workflow_env, job_env, tainted_refs=tainted),
                refs=dict(tainted),
                subject_fields_empty=subject_fields_empty,
                agent_only=model_only,
            )
            steps = job_data.get("steps")
            for step in steps if isinstance(steps, list) else []:
                if isinstance(step, LineDict):
                    _absorb_step(state, step)
                    if signatures is not None and step.get("id") and _is_agent_step(step, signatures):
                        state.agent_steps.add(str(step["id"]).lower())
            outputs = job_data.get("outputs")
            for name, value in outputs.items() if isinstance(outputs, Mapping) else []:
                sources = state.sources(str(value), state.env)
                if sources:
                    tainted[f"needs.{job_id}.outputs.{name}".lower()] = sources
        if len(tainted) == before:
            break
    return tainted


def scan_workflow_file(
    file_path: Path,
    signatures: list[ActionSignature] | None = None,
) -> list[Finding]:
    """Scan a single GitHub Actions or GitLab CI YAML file and return all security findings."""
    if signatures is None:
        signatures = load_signatures()

    root, raw_lines = load_workflow_file(file_path)
    if not isinstance(root, LineDict):
        return []

    findings: list[Finding] = []
    triggers = _extract_triggers(root)
    workflow_env = root.get("env") if isinstance(root.get("env"), Mapping) else None
    workflow_perms = root.get("permissions")

    jobs = root.get("jobs")
    if isinstance(jobs, LineDict):
        job_output_taint = _collect_job_output_taint(
            jobs, workflow_env, bool(triggers) and triggers <= NO_SUBJECT_TRIGGERS
        )
        for job_id, job_data in jobs.items():
            if not isinstance(job_data, LineDict):
                continue
            findings.extend(
                _scan_github_job(
                    file_path=file_path,
                    raw_lines=raw_lines,
                    triggers=triggers,
                    workflow_env=workflow_env,
                    workflow_perms=workflow_perms,
                    job_id=str(job_id),
                    job_data=job_data,
                    signatures=signatures,
                    job_output_taint=job_output_taint,
                    job_model_output=_collect_job_output_taint(jobs, workflow_env, False, signatures),
                )
            )
    else:
        # Also support GitLab CI top-level job definitions (`script:` blocks)
        findings.extend(
            _scan_gitlab_jobs(
                file_path=file_path,
                raw_lines=raw_lines,
                root=root,
                signatures=signatures,
            )
        )

    return findings


def _scan_github_job(
    *,
    file_path: Path,
    raw_lines: list[str],
    triggers: set[str],
    workflow_env: Mapping[str, Any] | None,
    workflow_perms: Any,
    job_id: str,
    job_data: LineDict,
    signatures: list[ActionSignature],
    job_output_taint: Mapping[str, list[str]],
    job_model_output: Mapping[str, list[str]],
) -> list[Finding]:
    findings: list[Finding] = []
    job_env = job_data.get("env") if isinstance(job_data.get("env"), Mapping) else None
    taint_state = TaintState(
        env=collect_tainted_env_map(workflow_env, job_env, tainted_refs=job_output_taint),
        refs=dict(job_output_taint),
        subject_fields_empty=bool(triggers) and triggers <= NO_SUBJECT_TRIGGERS,
    )
    job_perms = job_data.get("permissions", workflow_perms)
    job_if = str(job_data.get("if") or "")
    runs_on = str(job_data.get("runs-on") or "")

    steps = job_data.get("steps")
    if not isinstance(steps, list):
        return findings

    has_ai_step = False
    agent_holds_token = False
    agent_unsandboxed = False
    model_state = TaintState(refs=dict(job_model_output), agent_only=True)
    job_fully_guarded = _guard_strength(job_if) == "full"
    output_risk = bool(triggers & OUTPUT_RISK_TRIGGERS) or not triggers
    first_ai_step_line = job_data.__line__
    first_ai_tool_id: str | None = None
    has_egress_firewall = "firewall" in runs_on.lower()
    has_untrusted_pr_checkout = False
    untrusted_checkout_line = job_data.__line__
    unsafe_pr_checkout = False

    # Check job-level `if:` for spoofable [bot] condition (AIA003)
    if SPOOFABLE_BOT_RE.search(job_if):
        line_num = job_data.get_key_line("if")
        findings.append(
            _make_finding(
                rule_id="AIA003",
                file_path=file_path,
                line=line_num,
                col=job_data.get_key_col("if"),
                job_id=job_id,
                step_name=None,
                tool_id=None,
                snippet=_get_snippet(raw_lines, line_num),
                message=(
                    f"Job '{job_id}' uses a spoofable '[bot]' suffix check in `if: {job_if}`. "
                    "Any user can create a GitHub App ending in `[bot]` to bypass this gate."
                ),
            )
        )

    for idx, step in enumerate(steps):
        if not isinstance(step, LineDict):
            continue
        step_name = str(step.get("name") or f"step #{idx + 1}")
        step_env = step.get("env") if isinstance(step.get("env"), Mapping) else None
        step_if = str(step.get("if") or "")
        uses_val = str(step.get("uses") or "")
        run_val = str(step.get("run") or "")
        with_block = step.get("with") if isinstance(step.get("with"), LineDict) else LineDict()

        # Detect egress firewall step (step-security/harden-runner defaults to audit-only)
        if "step-security/harden-runner" in uses_val.lower():
            if str(with_block.get("egress-policy") or "").strip().lower() == "block":
                has_egress_firewall = True

        # Detect untrusted PR checkout inside pull_request_target
        if "actions/checkout" in uses_val.lower() and "pull_request_target" in triggers:
            ref_val = str(with_block.get("ref") or "")
            if PR_HEAD_CHECKOUT_RE.search(ref_val):
                has_untrusted_pr_checkout = True
                untrusted_checkout_line = with_block.get_key_line("ref", step.__line__)
                # Current checkout releases refuse fork PR code here, unless told otherwise
                opted_in = str(with_block.get("allow-unsafe-pr-checkout") or "").strip().lower() == "true"
                pinned = re.search(r"@[0-9a-f]{40}\b", uses_val.lower())
                # Credentials kept out of a side folder is the documented way to inspect PR code
                isolated = with_block.get("path") and str(with_block.get("persist-credentials")).lower() == "false"
                unsafe_pr_checkout = unsafe_pr_checkout or ((opted_in or bool(pinned)) and not isolated)

        # Check step-level `if:` for spoofable [bot] check (AIA003)
        if SPOOFABLE_BOT_RE.search(step_if):
            line_num = step.get_key_line("if")
            findings.append(
                _make_finding(
                    rule_id="AIA003",
                    file_path=file_path,
                    line=line_num,
                    col=step.get_key_col("if"),
                    job_id=job_id,
                    step_name=step_name,
                    tool_id=None,
                    snippet=_get_snippet(raw_lines, line_num),
                    message=(
                        f"Step '{step_name}' uses a spoofable '[bot]' suffix check in `if: {step_if}`."
                    ),
                )
            )

        tainted_env = taint_state.scoped(step_env)
        guard = _guard_strength(job_if, step_if)
        fetch_guarded = guard is not None
        limited_impact = (
            fetch_guarded
            or _has_cleared_token(step_env)
            or _is_read_only_token(job_perms)
            or (triggers and triggers <= CALLER_GATED_TRIGGERS)
        )
        taint_severity = Severity.MEDIUM if guard == "full" else (Severity.HIGH if limited_impact else None)

        # AIA010: Agent output reaching a shell, git command, or checkout target
        if output_risk:
            for sink_severity, sink in _agent_output_sinks(run_val, uses_val, with_block, step_env, model_state):
                sink_key = "run" if run_val else "uses"
                sink_line = step.get_key_line(sink_key, step.__line__)
                findings.append(
                    _make_finding(
                        rule_id="AIA010",
                        file_path=file_path,
                        line=sink_line,
                        col=step.get_key_col(sink_key),
                        job_id=job_id,
                        step_name=step_name,
                        tool_id=first_ai_tool_id,
                        snippet=_get_snippet(raw_lines, sink_line),
                        message=f"AI agent output {sink} in step '{step_name}'.",
                        severity=Severity.MEDIUM if guard == "full" else sink_severity,
                    )
                )

        # A PR checkout through `gh` or `git` runs regardless of actions/checkout's refusal
        if run_val and "pull_request_target" in triggers and PR_CHECKOUT_COMMAND_RE.search(run_val):
            has_untrusted_pr_checkout = True
            unsafe_pr_checkout = True
            untrusted_checkout_line = step.get_key_line("run", step.__line__)

        # Check `uses:` against AI Action signatures
        if uses_val:
            sig, version_ref = _match_action_signature(uses_val, signatures)
            if sig is not None:
                if not has_ai_step:
                    has_ai_step = True
                    first_ai_step_line = step.get_key_line("uses", step.__line__)
                    first_ai_tool_id = sig.id
                agent_holds_token = agent_holds_token or not _has_cleared_token(step_env)
                read_only_sandbox = str(with_block.get("sandbox") or "").strip().lower() == "read-only"
                agent_unsandboxed = agent_unsandboxed or not read_only_sandbox
                model_state.agent_steps.update({str(step["id"]).lower()} if step.get("id") else set())
                if (read_only_sandbox or _agent_lacks_shell(with_block)) and taint_severity is None:
                    taint_severity = Severity.HIGH

                # AIA004: Check vulnerable or unpinned AI Action version
                findings.extend(
                    _check_action_version(
                        file_path=file_path,
                        raw_lines=raw_lines,
                        job_id=job_id,
                        step=step,
                        step_name=step_name,
                        sig=sig,
                        uses_val=uses_val,
                        version_ref=version_ref,
                    )
                )

                # Inspect `with:` inputs for AIA001, AIA002, AIA003, AIA007
                findings.extend(
                    _check_action_with_inputs(
                        file_path=file_path,
                        raw_lines=raw_lines,
                        job_id=job_id,
                        step=step,
                        step_name=step_name,
                        sig=sig,
                        with_block=with_block,
                        tainted_env=tainted_env,
                        taint_state=taint_state,
                        read_only_sandbox=read_only_sandbox,
                        taint_severity=taint_severity,
                    )
                )

                # AIA001: Env vars set on the agent step are readable by the agent
                for env_key, env_value in (step_env or {}).items():
                    env_sources = taint_state.sources(str(env_value or ""), tainted_env)
                    if env_sources:
                        env_line = step_env.get_key_line(str(env_key), step.__line__)
                        findings.append(
                            _make_finding(
                                rule_id="AIA001",
                                file_path=file_path,
                                line=env_line,
                                col=step_env.get_key_col(str(env_key), step.__col__),
                                job_id=job_id,
                                step_name=step_name,
                                tool_id=sig.id,
                                snippet=_get_snippet(raw_lines, env_line),
                                message=(
                                    f"Untrusted input ({', '.join(env_sources)}) is exposed to {sig.name} "
                                    f"through `env.{env_key}` (PromptPwnd indirect prompt injection)."
                                ),
                                severity=taint_severity,
                            )
                        )

                # AIA009: Agent reads attacker-written text through the gh CLI
                agent_text = " ".join(str(v) for v in with_block.values() if v is not None)
                if (
                    triggers & FETCH_RISK_TRIGGERS
                    and not fetch_guarded
                    and (GH_FETCH_RE.search(agent_text) or GH_TOOL_GRANT_RE.search(agent_text))
                ):
                    uses_line = step.get_key_line("uses", step.__line__)
                    findings.append(
                        _make_finding(
                            rule_id="AIA009",
                            file_path=file_path,
                            line=uses_line,
                            col=step.get_key_col("uses"),
                            job_id=job_id,
                            step_name=step_name,
                            tool_id=sig.id,
                            snippet=_get_snippet(raw_lines, uses_line),
                            message=(
                                f"{sig.name} can read issue or PR text through `gh` on an externally "
                                "reachable trigger, with no `author_association` gate."
                            ),
                        )
                    )

        # Check `run:` script for AI CLI invocations & unpinned MCP servers
        if run_val:
            run_line = step.get_key_line("run", step.__line__)
            cli_sigs = _match_cli_signatures(run_val, signatures)
            if cli_sigs:
                if not has_ai_step:
                    has_ai_step = True
                    first_ai_step_line = run_line
                    first_ai_tool_id = cli_sigs[0].id
                agent_holds_token = agent_holds_token or not _has_cleared_token(step_env)
                agent_unsandboxed = True
                model_state.agent_steps.update({str(step["id"]).lower()} if step.get("id") else set())

                for cli_sig in cli_sigs:
                    # AIA001: Tainted input in CLI command
                    taint_sources = taint_state.sources(run_val, tainted_env)
                    if taint_sources:
                        findings.append(
                            _make_finding(
                                rule_id="AIA001",
                                file_path=file_path,
                                line=run_line,
                                col=step.get_key_col("run"),
                                job_id=job_id,
                                step_name=step_name,
                                tool_id=cli_sig.id,
                                snippet=_get_snippet(raw_lines, run_line),
                                message=(
                                    f"Untrusted input ({', '.join(taint_sources)}) flows into "
                                    f"{cli_sig.name} CLI invocation in `run:` block (PromptPwnd risk)."
                                ),
                                severity=taint_severity,
                            )
                        )

                    # AIA009: Agent reads attacker-written text through the gh CLI
                    if (
                        triggers & FETCH_RISK_TRIGGERS
                        and not fetch_guarded
                        and not taint_sources
                        and (GH_FETCH_RE.search(run_val) or GH_TOOL_GRANT_RE.search(run_val))
                    ):
                        findings.append(
                            _make_finding(
                                rule_id="AIA009",
                                file_path=file_path,
                                line=run_line,
                                col=step.get_key_col("run"),
                                job_id=job_id,
                                step_name=step_name,
                                tool_id=cli_sig.id,
                                snippet=_get_snippet(raw_lines, run_line),
                                message=(
                                    f"{cli_sig.name} can read issue or PR text through `gh` on an externally "
                                    "reachable trigger, with no `author_association` gate."
                                ),
                            )
                        )

                    # AIA002: Dangerous CLI flags
                    for flag_pat in cli_sig.dangerous_arg_patterns:
                        if re.search(flag_pat.pattern, run_val):
                            findings.append(
                                _make_finding(
                                    rule_id="AIA002",
                                    file_path=file_path,
                                    line=run_line,
                                    col=step.get_key_col("run"),
                                    job_id=job_id,
                                    step_name=step_name,
                                    tool_id=cli_sig.id,
                                    snippet=_get_snippet(raw_lines, run_line),
                                    message=(
                                        f"{cli_sig.name} invoked with dangerous flag matching "
                                        f"`{flag_pat.pattern}`: {flag_pat.reason}"
                                    ),
                                )
                            )

            # AIA011: Job pushes to the default branch after an agent ran
            if has_ai_step and output_risk and not job_fully_guarded and DEFAULT_BRANCH_PUSH_RE.search(run_val):
                findings.append(
                    _make_finding(
                        rule_id="AIA011",
                        file_path=file_path,
                        line=run_line,
                        col=step.get_key_col("run"),
                        job_id=job_id,
                        step_name=step_name,
                        tool_id=first_ai_tool_id,
                        snippet=_get_snippet(raw_lines, run_line),
                        message=f"Job '{job_id}' pushes to the default branch after an AI agent ran, with no review.",
                    )
                )

            # AIA007: Unpinned MCP server in `run:`
            for pkg_name in _iter_unpinned_mcp_packages(run_val):
                findings.append(
                    _make_finding(
                        rule_id="AIA007",
                        file_path=file_path,
                        line=run_line,
                        col=step.get_key_col("run"),
                        job_id=job_id,
                        step_name=step_name,
                        tool_id=first_ai_tool_id,
                        snippet=_get_snippet(raw_lines, run_line),
                        message=(
                            f"MCP server package `{pkg_name}` is dynamically executed via npx/uvx "
                            "without an exact version pin."
                        ),
                    )
                )

        _absorb_step(taint_state, step)
        _absorb_step(model_state, step)

    # Job-level checks that apply only if the job runs at least one AI agent step
    if has_ai_step:
        externally_reachable = bool(triggers & UNTRUSTED_TRIGGERS) or not triggers

        # AIA005: Over-privileged or missing permissions block on untrusted triggers
        if externally_reachable and agent_holds_token and not job_fully_guarded:
            if _is_overprivileged_permissions(job_perms):
                perm_line = job_data.get_key_line("permissions", job_data.__line__)
                findings.append(
                    _make_finding(
                        rule_id="AIA005",
                        file_path=file_path,
                        line=perm_line,
                        col=job_data.get_key_col("permissions"),
                        job_id=job_id,
                        step_name=None,
                        tool_id=first_ai_tool_id,
                        snippet=_get_snippet(raw_lines, perm_line),
                        message=(
                            f"AI job '{job_id}' runs with over-privileged or default `GITHUB_TOKEN` "
                            "permissions on an externally reachable workflow trigger."
                        ),
                    )
                )

        # AIA006: Missing egress firewall
        privileged_reach = bool(triggers & PRIVILEGED_UNTRUSTED_TRIGGERS) or not triggers
        if privileged_reach and agent_unsandboxed and not has_egress_firewall and not job_fully_guarded:
            findings.append(
                _make_finding(
                    rule_id="AIA006",
                    file_path=file_path,
                    line=first_ai_step_line,
                    col=job_data.__col__,
                    job_id=job_id,
                    step_name=None,
                    tool_id=first_ai_tool_id,
                    snippet=_get_snippet(raw_lines, first_ai_step_line),
                    message=(
                        f"AI job '{job_id}' executes an autonomous agent without an outbound network "
                        "egress firewall (`step-security/harden-runner` or firewall runner)."
                    ),
                )
            )

        # AIA008: pull_request_target + untrusted PR head checkout + AI agent
        if has_untrusted_pr_checkout:
            findings.append(
                _make_finding(
                    rule_id="AIA008",
                    file_path=file_path,
                    line=untrusted_checkout_line,
                    col=1,
                    job_id=job_id,
                    step_name=None,
                    tool_id=first_ai_tool_id,
                    snippet=_get_snippet(raw_lines, untrusted_checkout_line),
                    message=(
                        f"Job '{job_id}' is triggered by `pull_request_target`, checks out untrusted "
                        "PR head code, and runs an AI coding agent—allowing malicious repo files/hooks "
                        "to execute with base repository secrets."
                        + (
                            " Current actions/checkout releases refuse fork PR code here, so same-repository "
                            "PRs and older pinned versions are the remaining risk."
                            if not unsafe_pr_checkout
                            else ""
                        )
                    ),
                    severity=(
                        Severity.MEDIUM if job_fully_guarded else (Severity.HIGH if not unsafe_pr_checkout else None)
                    ),
                )
            )

    return findings


def _check_action_version(
    *,
    file_path: Path,
    raw_lines: list[str],
    job_id: str,
    step: LineDict,
    step_name: str,
    sig: ActionSignature,
    uses_val: str,
    version_ref: str | None,
) -> list[Finding]:
    findings: list[Finding] = []
    uses_line = step.get_key_line("uses", step.__line__)
    uses_col = step.get_key_col("uses", step.__col__)

    if not version_ref or version_ref.lower() in {"main", "master", "head", "latest"}:
        findings.append(
            _make_finding(
                rule_id="AIA004",
                file_path=file_path,
                line=uses_line,
                col=uses_col,
                job_id=job_id,
                step_name=step_name,
                tool_id=sig.id,
                snippet=_get_snippet(raw_lines, uses_line),
                message=(
                    f"AI Action `{uses_val}` is pinned to a mutable branch reference (`@{version_ref or 'none'}`). "
                    "Pin to an immutable release tag or commit SHA."
                ),
            )
        )
        return findings

    if re.fullmatch(r"[vV]?\d+(?:\.\d+)?", version_ref):
        findings.append(
            _make_finding(
                rule_id="AIA004",
                file_path=file_path,
                line=uses_line,
                col=uses_col,
                job_id=job_id,
                step_name=step_name,
                tool_id=sig.id,
                snippet=_get_snippet(raw_lines, uses_line),
                message=(
                    f"AI Action `{uses_val}` uses floating tag `@{version_ref}`, which moves with each "
                    "release. Pin to a full release version or commit SHA."
                ),
                severity=Severity.MEDIUM,
            )
        )
        return findings

    if sig.min_safe_version:
        min_tuple = _parse_semver_tuple(sig.min_safe_version)
        cur_tuple = _parse_semver_tuple(version_ref)
        if min_tuple and cur_tuple and cur_tuple < min_tuple:
            advisory_note = f" (see {sig.advisory_url})" if sig.advisory_url else ""
            findings.append(
                _make_finding(
                    rule_id="AIA004",
                    file_path=file_path,
                    line=uses_line,
                    col=uses_col,
                    job_id=job_id,
                    step_name=step_name,
                    tool_id=sig.id,
                    snippet=_get_snippet(raw_lines, uses_line),
                    message=(
                        f"`{uses_val}` uses vulnerable version `{version_ref}` below minimum safe "
                        f"version `v{sig.min_safe_version}`{advisory_note}."
                    ),
                )
            )
    return findings


def _check_action_with_inputs(
    *,
    file_path: Path,
    raw_lines: list[str],
    job_id: str,
    step: LineDict,
    step_name: str,
    sig: ActionSignature,
    with_block: LineDict,
    tainted_env: Mapping[str, list[str]],
    taint_state: TaintState,
    read_only_sandbox: bool,
    taint_severity: Severity | None,
) -> list[Finding]:
    findings: list[Finding] = []
    prompt_keys_lower = {k.lower() for k in sig.prompt_inputs}

    for key, raw_val in with_block.items():
        if raw_val is None:
            continue
        key_str = str(key)
        val_str = str(raw_val)
        key_line = with_block.get_key_line(key_str, step.__line__)
        key_col = with_block.get_key_col(key_str, step.__col__)

        # AIA001: Untrusted event input flowing into a prompt sink
        if key_str.lower() in prompt_keys_lower:
            taint_sources = taint_state.sources(val_str, tainted_env)
            if taint_sources:
                findings.append(
                    _make_finding(
                        rule_id="AIA001",
                        file_path=file_path,
                        line=key_line,
                        col=key_col,
                        job_id=job_id,
                        step_name=step_name,
                        tool_id=sig.id,
                        snippet=_get_snippet(raw_lines, key_line),
                        message=(
                            f"Untrusted input ({', '.join(taint_sources)}) is interpolated into "
                            f"`with.{key_str}` of {sig.name} (PromptPwnd indirect prompt injection)."
                        ),
                        severity=taint_severity,
                    )
                )

        # AIA003: Specific dangerous input values (e.g. allowed_non_write_users: "*")
        if key_str in sig.dangerous_inputs:
            expected_bad = sig.dangerous_inputs[key_str]
            if val_str.strip().lower() == expected_bad.lower():
                rule_id = "AIA003" if "user" in key_str.lower() or "bot" in key_str.lower() else "AIA002"
                # Open access is sometimes deliberate (public triage), unlike a spoofable check
                access_severity = Severity.MEDIUM if read_only_sandbox else Severity.HIGH
                findings.append(
                    _make_finding(
                        rule_id=rule_id,
                        file_path=file_path,
                        line=key_line,
                        col=key_col,
                        job_id=job_id,
                        step_name=step_name,
                        tool_id=sig.id,
                        snippet=_get_snippet(raw_lines, key_line),
                        message=(
                            f"Insecure configuration `with.{key_str}: {val_str}` in {sig.name} "
                            "lets any GitHub user trigger the AI agent. Confirm this is deliberate and "
                            "that the agent has no shell, write, or secret access."
                        ),
                        severity=access_severity if rule_id == "AIA003" else None,
                    )
                )

        # AIA002: Dangerous CLI/tool flags passed inside `with:` arguments (e.g. claude_args, allowed_tools)
        for flag_pat in sig.dangerous_arg_patterns:
            if re.search(flag_pat.pattern, val_str):
                findings.append(
                    _make_finding(
                        rule_id="AIA002",
                        file_path=file_path,
                        line=key_line,
                        col=key_col,
                        job_id=job_id,
                        step_name=step_name,
                        tool_id=sig.id,
                        snippet=_get_snippet(raw_lines, key_line),
                        message=(
                            f"Dangerous agent argument matching `{flag_pat.pattern}` in "
                            f"`with.{key_str}` of {sig.name}: {flag_pat.reason}"
                        ),
                    )
                )

        # AIA007: Unpinned MCP server inside `with:` block (e.g. mcp_config)
        for pkg_name in _iter_unpinned_mcp_packages(val_str):
            findings.append(
                _make_finding(
                    rule_id="AIA007",
                    file_path=file_path,
                    line=key_line,
                    col=key_col,
                    job_id=job_id,
                    step_name=step_name,
                    tool_id=sig.id,
                    snippet=_get_snippet(raw_lines, key_line),
                    message=(
                        f"MCP server package `{pkg_name}` in `with.{key_str}` is executed via "
                        "npx/uvx without an exact version pin."
                    ),
                )
            )

    return findings


def _scan_gitlab_jobs(
    *,
    file_path: Path,
    raw_lines: list[str],
    root: LineDict,
    signatures: list[ActionSignature],
) -> list[Finding]:
    """Scan GitLab CI job definitions (`script:` blocks and `variables:`)."""
    findings: list[Finding] = []
    global_vars = root.get("variables") if isinstance(root.get("variables"), Mapping) else None

    for job_name, job_body in root.items():
        if not isinstance(job_body, LineDict) or "script" not in job_body:
            continue
        job_vars = job_body.get("variables") if isinstance(job_body.get("variables"), Mapping) else None
        tainted_env = collect_tainted_env_map(global_vars, job_vars)

        script_block = job_body.get("script")
        raw_items = script_block if isinstance(script_block, list) else [script_block]
        rendered_script_lines: list[str] = []
        for item in raw_items:
            if isinstance(item, Mapping):
                for k, v in item.items():
                    rendered_script_lines.append(f"{k}: {v}")
            elif item is not None:
                rendered_script_lines.append(str(item))
        script_text = "\n".join(rendered_script_lines)
        script_line_num = job_body.get_key_line("script", job_body.__line__)

        # AIA007: Unpinned MCP server in GitLab script
        for pkg_name in _iter_unpinned_mcp_packages(script_text):
            findings.append(
                _make_finding(
                    rule_id="AIA007",
                    file_path=file_path,
                    line=script_line_num,
                    col=job_body.get_key_col("script"),
                    job_id=str(job_name),
                    step_name="script",
                    tool_id=None,
                    snippet=_get_snippet(raw_lines, script_line_num),
                    message=(
                        f"MCP server package `{pkg_name}` is dynamically executed via npx/uvx "
                        "without an exact version pin."
                    ),
                )
            )

        cli_sigs = _match_cli_signatures(script_text, signatures)
        for cli_sig in cli_sigs:
            taint_sources = find_all_taint_sources(script_text, tainted_env)
            if taint_sources:
                findings.append(
                    _make_finding(
                        rule_id="AIA001",
                        file_path=file_path,
                        line=script_line_num,
                        col=job_body.get_key_col("script"),
                        job_id=str(job_name),
                        step_name="script",
                        tool_id=cli_sig.id,
                        snippet=_get_snippet(raw_lines, script_line_num),
                        message=(
                            f"Untrusted GitLab CI variable ({', '.join(taint_sources)}) flows into "
                            f"{cli_sig.name} CLI invocation in job '{job_name}' (PromptPwnd risk)."
                        ),
                    )
                )
            for flag_pat in cli_sig.dangerous_arg_patterns:
                if re.search(flag_pat.pattern, script_text):
                    findings.append(
                        _make_finding(
                            rule_id="AIA002",
                            file_path=file_path,
                            line=script_line_num,
                            col=job_body.get_key_col("script"),
                            job_id=str(job_name),
                            step_name="script",
                            tool_id=cli_sig.id,
                            snippet=_get_snippet(raw_lines, script_line_num),
                            message=(
                                f"{cli_sig.name} invoked with dangerous flag `{flag_pat.pattern}` "
                                f"in GitLab CI job '{job_name}': {flag_pat.reason}"
                            ),
                        )
                    )

    return findings


def _is_overprivileged_permissions(perms: Any) -> bool:
    """Return True if a workflow/job permissions block is missing, write-all, or grants a dangerous write scope."""
    if perms is None:
        return True
    if isinstance(perms, str):
        return perms.strip().lower() in {"write-all"}
    if isinstance(perms, Mapping):
        return any(str(perms.get(scope) or "").strip().lower() == "write" for scope in ("contents", "actions", "packages"))
    return False


def _make_finding(
    *,
    rule_id: str,
    file_path: Path,
    line: int,
    col: int,
    job_id: str | None,
    step_name: str | None,
    tool_id: str | None,
    snippet: str | None,
    message: str,
    severity: Severity | None = None,
) -> Finding:
    meta = RULES_CATALOG[rule_id]
    return Finding(
        rule_id=rule_id,
        rule_name=meta.name,
        severity=severity or meta.severity,
        file_path=file_path,
        line=line,
        column=col,
        job_id=job_id,
        step_name=step_name,
        tool_id=tool_id,
        snippet=snippet,
        message=message,
        remediation=meta.remediation,
    )
