"""Default agent launches and management subcommands have distinct security roles."""

import pytest

from ci_agent_audit.rules import _match_cli_signatures
from ci_agent_audit.signatures_loader import load_signatures


@pytest.mark.parametrize("binary", ["agent", "cursor-agent"])
@pytest.mark.parametrize("args", ['-p "$BODY"', 'agent "$BODY"', '"$BODY"', "resume"])
def test_cursor_agent_launches(binary, args):
    matches = _match_cli_signatures(f"{binary} {args}", load_signatures())
    assert "cursor-cli" in {s.id for s in matches}


@pytest.mark.parametrize("binary", ["agent", "cursor-agent"])
@pytest.mark.parametrize(
    "args",
    [
        "login",
        "logout",
        "status",
        "whoami",
        "about",
        "models",
        "mcp list",
        "sandbox enable",
        "worker start",
        "update",
        "ls",
        "create-chat",
        "help",
        "--help",
        "--version",
    ],
)
def test_cursor_management_commands_are_not_agent_sinks(binary, args):
    matches = _match_cli_signatures(f"{binary} {args}", load_signatures())
    assert "cursor-cli" not in {s.id for s in matches}


def test_management_command_does_not_hide_later_agent_launch():
    matches = _match_cli_signatures(
        'agent login && agent -p "$BODY"', load_signatures()
    )
    assert "cursor-cli" in {s.id for s in matches}
