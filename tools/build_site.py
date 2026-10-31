"""Build the project website into _site."""

from __future__ import annotations

from html import escape
import json
from pathlib import Path
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "website"
PACKAGE = ROOT / "src" / "ci_agent_audit"
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tools"), str(SOURCE)]

from ci_agent_audit import __version__  # noqa: E402
from ci_agent_audit.rules import RULES_CATALOG  # noqa: E402
from ci_agent_audit.signatures_loader import load_signatures  # noqa: E402
from run_benchmark import Score, load_cases, run  # noqa: E402
from site_scan import scan_text  # noqa: E402

EXAMPLES = [
    ("triage", "Issue triage", ".github/workflows/triage.yml"),
    ("review", "PR review", ".github/workflows/review.yml"),
    ("gitlab", "GitLab job", ".gitlab-ci.yml"),
    ("hardened", "Locked down", ".github/workflows/triage.yml"),
]

QUESTIONS = {
    "AIA001": ("Can outsiders write part of the agent's prompt?", "Their text can become instructions, even after passing through variables, step outputs, or files."),
    "AIA002": ("Are the agent's safety checks turned off?", "Flags like --dangerously-skip-permissions remove its guardrails."),
    "AIA003": ("Can anyone trigger the agent?", "A [bot] name check can be spoofed, and \"*\" lets every user in."),
    "AIA004": ("Is the agent action outdated or on a moving version?", "A known bug or a changed release could reach your pipeline."),
    "AIA005": ("Does the agent hold too much access?", "A hijacked agent with write access can change your code."),
    "AIA006": ("Can the agent send data anywhere?", "With no network limits, stolen secrets can leave the runner."),
    "AIA007": ("Does CI download MCP servers with no fixed version?", "A compromised package would run next to your secrets."),
    "AIA008": ("Does a privileged job run the agent on untrusted PR code?", "Files in the PR can run with your repository's secrets."),
    "AIA009": ("Is the agent told or allowed to fetch issue text with gh?", "The prompt looks clean, but the agent still reads attacker text."),
    "AIA010": ("Does the model's answer reach a shell or git command?", "A hijacked answer becomes a command or a checkout of attacker code."),
    "AIA011": ("Is agent work pushed straight to main?", "Injected changes land without review."),
}

BENCHMARK_GROUPS = {
    "direct": "Direct risks",
    "composite": "Local composite actions",
    "reusable": "Reusable workflows",
    "guards": "Guard and data-flow traps",
    "safe": "Safe setups",
    "gaps": "Known gaps",
}

SUPPORT = [
    ("Ethereum (ERC20), BNB Chain (BEP20), Base, Arbitrum, Optimism, Polygon", "0x7C524d172F2bf750e3f7b4Df0339B3fFb09F9ADb"),
    ("Bitcoin", "bc1qcvdafsre6tlfpsdnv2s4ltwvy9tlgkjj6ag4gu"),
    ("Solana", "Fv9k74qakg1L7ehMaJ3SBXxVbTKg2WuM5AjW2KLM3nVH"),
    ("Tron (TRC20)", "TJVfPm5wJnKjD5ZzBRhMXtzB1aF17Kbyuz"),
]


def _rules() -> str:
    rows = []
    for rule_id, meta in sorted(RULES_CATALOG.items()):
        question, why = QUESTIONS[rule_id]
        severity = meta.severity.value
        rows.append(
            f'<tr id="{rule_id}"><th scope="row"><code>{rule_id}</code></th>'
            f'<td><span class="tag {severity}">{severity.title()}</span></td>'
            f"<td><strong>{escape(question)}</strong><span>{escape(why)}</span></td></tr>"
        )
    return "\n".join(rows)


def _tools() -> str:
    return "\n".join(f"<li>{escape(signature.name)}</li>" for signature in load_signatures())


def _support() -> str:
    return "\n".join(
        f'<div class="wallet"><p>{escape(network)}</p>'
        f'<div><code>{address}</code><button type="button" class="copy" data-copy="{address}">Copy</button></div></div>'
        for network, address in SUPPORT
    )


def _benchmark() -> dict[str, str]:
    cases = load_cases()
    total = Score()
    rows = []
    for group, score in run(cases).items():
        total.add(score)
        rows.append(
            f'<tr><th scope="row">{escape(BENCHMARK_GROUPS[group])}</th><td>{len(cases[group])}</td>'
            f"<td>{score.found}</td><td>{len(score.missed)}</td><td>{len(score.false_alarms)}</td></tr>"
        )
    return {
        "benchmark": "\n".join(rows),
        "case_count": str(sum(len(items) for items in cases.values())),
        "recall": f"{total.recall:.1%}",
        "precision": f"{total.precision:.0%}",
    }


def _examples() -> str:
    data = []
    for slug, label, file_name in EXAMPLES:
        text = (SOURCE / "examples" / f"{slug}.yml").read_text(encoding="utf-8")
        data.append({"slug": slug, "label": label, "file": file_name, "text": text, "result": json.loads(scan_text(text))})
    return json.dumps(data).replace("</", "<\\/")


def _write_scanner(path: Path) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(SOURCE / "site_scan.py", "site_scan.py")
        for file in sorted(PACKAGE.rglob("*")):
            if file.suffix in {".py", ".yaml"}:
                archive.write(file, file.relative_to(PACKAGE.parent).as_posix())


def build(out: Path) -> None:
    shutil.rmtree(out, ignore_errors=True)
    shutil.copytree(SOURCE, out, ignore=shutil.ignore_patterns("__pycache__", "examples", "site_scan.py"))
    page = (SOURCE / "index.html").read_text(encoding="utf-8")
    for token, value in {
        "version": __version__,
        "rules": _rules(),
        "tools": _tools(),
        "support": _support(),
        "examples": _examples(),
        **_benchmark(),
    }.items():
        page = page.replace(f"<!-- {token} -->", value)
    (out / "index.html").write_text(page, encoding="utf-8")
    _write_scanner(out / "scanner.zip")


if __name__ == "__main__":
    build(ROOT / "_site")
