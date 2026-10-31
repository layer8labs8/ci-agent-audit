"""Keep the labelled benchmark passing, so its published numbers stay true."""

from __future__ import annotations

from pathlib import Path

import pytest

from run_benchmark import load_cases, score_case

CASES = [case for group in load_cases().values() for case in group]
COVERED = [case for case in CASES if not case.get("gap")]
GAPS = [case for case in CASES if case.get("gap")]


def _name(case: dict) -> str:
    return case["name"]


def test_readme_states_the_current_case_count() -> None:
    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    assert f"{len(CASES)} small repositories" in readme


def test_case_names_are_unique() -> None:
    names = [case["name"] for case in CASES]
    assert len(names) == len(set(names))


@pytest.mark.parametrize("case", COVERED, ids=_name)
def test_covered_case(case: dict) -> None:
    score = score_case(case)
    assert not score.missed
    assert not score.false_alarms


@pytest.mark.parametrize("case", GAPS, ids=_name)
def test_known_gap_is_still_a_gap(case: dict) -> None:
    assert score_case(case).missed, "This gap is closed. Remove its `gap` label."
