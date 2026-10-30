"""Loader and schema validator for 1-file-per-tool AI Action/CLI signatures."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml

from ci_agent_audit.models import ActionSignature, DangerousFlagPattern

REQUIRED_SIGNATURE_FIELDS = {"id", "name", "vendor", "description"}


class SignatureValidationError(ValueError):
    """Raised when a signature YAML file does not conform to the expected schema."""


def parse_signature_dict(data: dict[str, Any], source: str = "<memory>") -> ActionSignature:
    """Validate and construct an ActionSignature from a parsed YAML dictionary."""
    if not isinstance(data, dict):
        raise SignatureValidationError(f"{source}: Signature root must be a YAML mapping/dictionary.")

    missing = REQUIRED_SIGNATURE_FIELDS - set(data.keys())
    if missing:
        raise SignatureValidationError(
            f"{source}: Missing required fields: {', '.join(sorted(missing))}"
        )

    action_prefixes = data.get("action_prefixes") or []
    cli_binaries = data.get("cli_binaries") or []
    if not action_prefixes and not cli_binaries:
        raise SignatureValidationError(
            f"{source}: Signature must define at least one of 'action_prefixes' or 'cli_binaries'."
        )

    raw_patterns = data.get("dangerous_arg_patterns") or []
    patterns: list[DangerousFlagPattern] = []
    for idx, item in enumerate(raw_patterns):
        if not isinstance(item, dict) or "pattern" not in item or "reason" not in item:
            raise SignatureValidationError(
                f"{source}: dangerous_arg_patterns[{idx}] must contain 'pattern' and 'reason'."
            )
        patterns.append(
            DangerousFlagPattern(
                pattern=str(item["pattern"]),
                reason=str(item["reason"]),
            )
        )

    dangerous_inputs_raw = data.get("dangerous_inputs") or {}
    if not isinstance(dangerous_inputs_raw, dict):
        raise SignatureValidationError(f"{source}: 'dangerous_inputs' must be a mapping.")

    return ActionSignature(
        id=str(data["id"]),
        name=str(data["name"]),
        vendor=str(data["vendor"]),
        description=str(data["description"]),
        action_prefixes=[str(x) for x in action_prefixes],
        non_agent_actions=[str(x) for x in (data.get("non_agent_actions") or [])],
        cli_binaries=[str(x) for x in cli_binaries],
        cli_packages=[str(x) for x in (data.get("cli_packages") or [])],
        cli_subcommands=[str(x) for x in (data.get("cli_subcommands") or [])],
        prompt_inputs=[str(x) for x in (data.get("prompt_inputs") or [])],
        cli_prompt_flags=[str(x) for x in (data.get("cli_prompt_flags") or [])],
        dangerous_inputs={str(k): str(v) for k, v in dangerous_inputs_raw.items()},
        dangerous_arg_patterns=patterns,
        min_safe_version=str(data["min_safe_version"]) if data.get("min_safe_version") else None,
        advisory_url=str(data["advisory_url"]) if data.get("advisory_url") else None,
        source_file=source,
    )


def load_signatures(extra_dirs: list[Path] | None = None) -> list[ActionSignature]:
    """Load all built-in signatures plus any signatures from extra directories."""
    builtin_dir = Path(__file__).parent / "signatures"
    search_dirs = [builtin_dir]
    if extra_dirs:
        search_dirs.extend(extra_dirs)

    signatures: dict[str, ActionSignature] = {}
    for directory in search_dirs:
        if not directory.exists():
            continue
        for yaml_file in sorted(directory.glob("*.y*ml")):
            raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            sig = parse_signature_dict(raw, source=str(yaml_file))
            signatures[sig.id] = sig

    return list(signatures.values())
