"""Command-line interface for ci-agent-audit."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

import yaml

from ci_agent_audit import __version__
from ci_agent_audit.fixer import apply_fixes_to_file
from ci_agent_audit.formatters import (
    format_github_annotations,
    format_json,
    format_sarif,
    format_text,
)
from ci_agent_audit.models import Finding, Severity
from ci_agent_audit.rules import RULES_CATALOG, scan_workflow_file
from ci_agent_audit.signatures_loader import SignatureValidationError, load_signatures


def _discover_workflow_files(paths: Sequence[str]) -> list[Path]:
    discovered: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            discovered.append(p)
        elif p.is_dir():
            for ext in ("*.yml", "*.yaml"):
                discovered.extend(sorted(p.rglob(ext)))
    # Deduplicate while preserving order
    seen: set[Path] = set()
    unique: list[Path] = []
    for item in discovered:
        resolved = item.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(item)
    return unique


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ci-agent-audit",
        description=(
            "Static security auditor for AI-powered CI/CD workflows (GitHub Actions & GitLab CI). "
            "Detects PromptPwnd indirect prompt injections, [bot] bypasses, dangerous agent flags, "
            "and unpinned MCP servers."
        ),
    )
    parser.add_argument("--version", action="version", version=f"ci-agent-audit {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    # `scan` command
    scan_p = subparsers.add_parser("scan", help="Scan workflow files or directories for AI CI security risks")
    scan_p.add_argument(
        "paths",
        nargs="*",
        default=[".github/workflows"],
        help="Workflow files or directories to scan (default: .github/workflows)",
    )
    scan_p.add_argument(
        "--format",
        choices=["text", "json", "sarif", "github"],
        default="text",
        help="Output format (default: text)",
    )
    scan_p.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level to report (default: low)",
    )
    scan_p.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical", "none"],
        default="high",
        help="Minimum severity level that causes a non-zero exit code (default: high)",
    )
    scan_p.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        help="Rule ID to ignore (can be specified multiple times, e.g. --ignore-rule AIA006)",
    )
    scan_p.add_argument(
        "--signatures-dir",
        action="append",
        default=[],
        help="Additional directory of custom YAML tool signatures",
    )
    scan_p.add_argument(
        "--output",
        "-o",
        help="Write formatted report to a file instead of stdout",
    )
    scan_p.add_argument(
        "--fix",
        action="store_true",
        help="Apply safe, deterministic fixes in-place before scanning",
    )

    # `rules` command
    subparsers.add_parser("rules", help="List all built-in security audit rules (AIA001 - AIA011)")

    # `explain` command
    explain_p = subparsers.add_parser("explain", help="Show detailed documentation and remediation for a rule")
    explain_p.add_argument("rule_id", help="Rule ID (e.g. AIA001)")

    # `signatures` command
    subparsers.add_parser("signatures", help="List all loaded AI Action & CLI tool signatures")

    # `validate-signatures` command (for contributors adding new 1-file signatures)
    val_p = subparsers.add_parser(
        "validate-signatures",
        help="Validate all built-in and custom YAML signature files against the schema",
    )
    val_p.add_argument(
        "dirs",
        nargs="*",
        default=[],
        help="Optional extra signature directories to validate",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "rules":
        for rule_id, meta in sorted(RULES_CATALOG.items()):
            print(f"{rule_id} [{meta.severity.value.upper()}] {meta.name}")
            print(f"  {meta.short_description}")
        return 0

    if args.command == "explain":
        rid = args.rule_id.upper()
        if rid not in RULES_CATALOG:
            print(f"Error: Unknown rule ID '{args.rule_id}'. Run `ci-agent-audit rules` to list rules.", file=sys.stderr)
            return 2
        meta = RULES_CATALOG[rid]
        print(f"Rule:        {meta.rule_id} ({meta.name})")
        print(f"Severity:    {meta.severity.value.upper()}")
        print(f"Summary:     {meta.short_description}\n")
        print(f"Description:\n  {meta.full_description}\n")
        print(f"Remediation:\n  {meta.remediation}\n")
        if meta.references:
            print("References:")
            for ref in meta.references:
                print(f"  - {ref}")
        return 0

    if args.command == "signatures":
        sigs = load_signatures()
        print(f"Loaded {len(sigs)} AI Action/CLI signatures:")
        for sig in sigs:
            actions = ", ".join(sig.action_prefixes) if sig.action_prefixes else "-"
            bins = ", ".join(sig.cli_binaries) if sig.cli_binaries else "-"
            print(f"  - {sig.id} ({sig.name} by {sig.vendor})")
            print(f"      Actions: {actions} | CLIs: {bins}")
        return 0

    if args.command == "validate-signatures":
        extra = [Path(d) for d in args.dirs]
        try:
            sigs = load_signatures(extra_dirs=extra)
        except SignatureValidationError as exc:
            print(f"✗ Signature validation failed: {exc}", file=sys.stderr)
            return 1
        print(f"✓ Successfully validated {len(sigs)} signature file(s).")
        return 0

    if args.command == "scan":
        extra_dirs = [Path(d) for d in args.signatures_dir]
        signatures = load_signatures(extra_dirs=extra_dirs)
        files = _discover_workflow_files(args.paths)

        # A security gate must not report success for files it never read
        if not files:
            print(f"Error: No workflow files found in: {', '.join(args.paths)}", file=sys.stderr)
            return 2

        if args.fix:
            for wf in files:
                modified, notes = apply_fixes_to_file(wf)
                if modified:
                    for note in notes:
                        print(f"[FIXED] {wf.as_posix()}: {note}", file=sys.stderr)

        min_sev = Severity(args.severity)
        ignored = {r.upper() for r in args.ignore_rule}

        all_findings: list[Finding] = []
        unreadable: list[Path] = []
        for wf in files:
            try:
                file_findings = scan_workflow_file(wf, signatures=signatures)
            except (yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
                unreadable.append(wf)
                print(f"Error: Could not scan {wf.as_posix()}: {exc}", file=sys.stderr)
                continue
            for f in file_findings:
                if f.rule_id.upper() in ignored:
                    continue
                if f.severity.rank >= min_sev.rank:
                    all_findings.append(f)

        if args.format == "json":
            output_text = format_json(all_findings)
        elif args.format == "sarif":
            output_text = format_sarif(all_findings)
        elif args.format == "github":
            output_text = format_github_annotations(all_findings)
        else:
            output_text = format_text(all_findings)

        if args.output:
            Path(args.output).write_text(output_text, encoding="utf-8")
        elif output_text:
            print(output_text)

        if unreadable:
            return 2

        if args.fail_on == "none":
            return 0
        fail_sev = Severity(args.fail_on)
        should_fail = any(f.severity.rank >= fail_sev.rank for f in all_findings)
        return 1 if should_fail else 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
