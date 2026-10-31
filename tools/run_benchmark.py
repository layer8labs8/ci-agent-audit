"""Score the scanner against the labelled cases in benchmark/cases.yml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sys
import tempfile

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ci_agent_audit.models import Finding, Severity  # noqa: E402
from ci_agent_audit.rules import dedupe_findings, scan_workflow_file  # noqa: E402

CASES = ROOT / "benchmark" / "cases.yml"


@dataclass
class Score:
    """Rule-level results for one group of cases."""

    found: int = 0
    missed: list[str] = field(default_factory=list)
    false_alarms: list[str] = field(default_factory=list)

    def add(self, other: Score) -> None:
        self.found += other.found
        self.missed += other.missed
        self.false_alarms += other.false_alarms

    @property
    def recall(self) -> float:
        total = self.found + len(self.missed)
        return self.found / total if total else 1.0

    @property
    def precision(self) -> float:
        total = self.found + len(self.false_alarms)
        return self.found / total if total else 1.0


def load_cases(path: Path = CASES) -> dict[str, list[dict]]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _scan_repository(root: Path) -> list[Finding]:
    workflows = sorted(root.glob(".github/workflows/*.y*ml"))
    gitlab = root / ".gitlab-ci.yml"
    findings: list[Finding] = []
    for file in [*workflows, *([gitlab] if gitlab.exists() else [])]:
        findings.extend(scan_workflow_file(file))
    return dedupe_findings(findings)


def score_case(case: dict) -> Score:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        for name, text in case["files"].items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        findings = _scan_repository(root)

    fired = {finding.rule_id for finding in findings}
    name = case["name"]
    expected = set(case.get("expect", []))
    score = Score(found=len(expected & fired))
    score.missed = [f"{name}: {rule}" for rule in sorted(expected - fired)]
    banned = set(case.get("forbid", []))
    if case.get("safe"):
        banned |= fired - set(case.get("allow", []))
    score.false_alarms = [f"{name}: {rule}" for rule in sorted(banned & fired)]
    if case.get("max_severity"):
        limit = Severity(case["max_severity"]).rank
        too_high = {finding.rule_id for finding in findings if finding.severity.rank > limit}
        score.false_alarms += [f"{name}: {rule} above {case['max_severity']}" for rule in sorted(too_high)]
    return score


def run(cases: dict[str, list[dict]]) -> dict[str, Score]:
    scores: dict[str, Score] = {}
    for group, items in cases.items():
        scores[group] = Score()
        for case in items:
            scores[group].add(score_case(case))
    return scores


def main() -> int:
    cases = load_cases()
    scores = run(cases)
    total = Score()
    print(f"{'Group':<12}{'Cases':>6}{'Found':>7}{'Missed':>8}{'False alarms':>14}")
    for group, score in scores.items():
        total.add(score)
        print(f"{group:<12}{len(cases[group]):>6}{score.found:>7}{len(score.missed):>8}{len(score.false_alarms):>14}")
    print(f"\nRecall {total.recall:.1%}  Precision {total.precision:.1%}")
    for label, items in (("Missed", total.missed), ("False alarms", total.false_alarms)):
        if items:
            print(f"\n{label}:")
            print("\n".join(f"  {item}" for item in items))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
