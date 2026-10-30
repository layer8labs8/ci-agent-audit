"""Deterministic auto-fix engine (`--fix`) for common AI CI/CD workflow misconfigurations."""

from __future__ import annotations

from pathlib import Path
import re

import yaml


def apply_fixes_to_file(file_path: Path) -> tuple[bool, list[str]]:
    """Apply safe, deterministic fixes to a workflow file and return (modified, applied_descriptions)."""
    # Bytes keep the file's own line endings, which text mode would normalize on Windows
    original = file_path.read_bytes().decode("utf-8")
    updated, descriptions = apply_fixes_to_text(original)
    if updated != original:
        file_path.write_bytes(updated.encode("utf-8"))
        return True, descriptions
    return False, []


def apply_fixes_to_text(content: str) -> tuple[str, list[str]]:
    """Apply deterministic security remediations to workflow YAML text."""
    descriptions: list[str] = []
    text = content
    newline = "\r\n" if "\r\n" in content else "\n"

    # Fix 1 (AIA004): Upgrade vulnerable anthropics/claude-code-action versions (< 1.0.94)
    # Branch refs are left alone: pinning @main to the safe minimum would be a large downgrade
    def _upgrade_claude_action(match: re.Match[str]) -> str:
        prefix = match.group(1)
        ver = match.group(2)
        cleaned = ver.lstrip("vV")
        parts = cleaned.split(".")
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            tup = (int(parts[0]), int(parts[1]), int(parts[2]))
            if tup < (1, 0, 94):
                descriptions.append(f"Upgraded vulnerable {prefix}@{ver} to @v1.0.94 (AIA004)")
                return f"{prefix}@v1.0.94"
        return match.group(0)

    text = re.sub(
        r"(anthropics/claude-code-action)@([A-Za-z0-9._-]+)",
        _upgrade_claude_action,
        text,
    )

    # Fix 2 (AIA003): Remove wildcard allowed_non_write_users / allowed_bots: "*"
    wildcard_users_re = re.compile(
        r"^([ \t]*(allowed_non_write_users|allowed_bots)[ \t]*:[ \t]*)(?:['\"]\*['\"]|\*)([ \t]*(?:#[^\r\n]*)?)(\r?)$",
        re.MULTILINE,
    )

    def _clear_wildcard(match: re.Match[str]) -> str:
        descriptions.append(f"Cleared insecure `{match.group(2)}: '*'` wildcard (AIA003)")
        return f'{match.group(1)}""{match.group(3)} # Fixed by ci-agent-audit (AIA003){match.group(4)}'

    text = wildcard_users_re.sub(_clear_wildcard, text)

    # Fix 3 (AIA005): Replace `permissions: write-all` with least-privilege `contents: read`
    write_all_re = re.compile(
        r"^([ \t]*)permissions[ \t]*:[ \t]*['\"]?write-all['\"]?[ \t]*(?=\r?$)",
        re.MULTILINE | re.IGNORECASE,
    )

    def _scope_permissions(match: re.Match[str]) -> str:
        descriptions.append("Replaced `permissions: write-all` with `contents: read` (AIA005)")
        indent = match.group(1)
        return f"{indent}permissions:{newline}{indent}  contents: read"

    text = write_all_re.sub(_scope_permissions, text)

    # Never hand back a workflow that the fixes turned into invalid YAML
    try:
        yaml.safe_load(text)
    except yaml.YAMLError:
        return content, []

    return text, descriptions
