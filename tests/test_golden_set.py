"""The golden set as a CI gate (§15.1).

If a case slips through, the change to the weights or the detectors is wrong -
not the test.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from ruamel.yaml import YAML
from test_scoring_support import make_candidate

from ctwatchtower.rules.loader import load_ruleset
from ctwatchtower.scoring.engine import score_candidate

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
_yaml = YAML(typ="safe")


def _cases(filename: str) -> list[dict]:
    return _yaml.load((FIXTURES / filename).read_text(encoding="utf-8"))


def _ruleset(tenant: str):
    return load_ruleset(RULES_DIR / "examples" / f"{tenant}.yaml")


def _ids(cases: list[dict]) -> list[str]:
    return [f"{c['tenant']}/{c['domain']}" for c in cases]


MALICIOUS = _cases("golden_malicious.yaml")
BENIGN = _cases("golden_benign.yaml")


@pytest.mark.parametrize("case", MALICIOUS, ids=_ids(MALICIOUS))
def test_golden_malicious(case: dict) -> None:
    result = score_candidate(_ruleset(case["tenant"]), make_candidate(case["domain"]))
    assert result.score >= case["min_score"], (
        f"{case['domain']}: {result.score} < {case['min_score']} — {result.matched}"
    )
    # An upper bound catches the other direction: weights creeping upwards.
    if "max_score" in case:
        assert result.score <= case["max_score"], (
            f"{case['domain']}: {result.score} > {case['max_score']} — {result.matched}"
        )
    for want in case.get("must_match", []):
        assert any(want in rule for rule in result.matched), f"{want} is missing from {result.matched}"


@pytest.mark.parametrize("case", BENIGN, ids=_ids(BENIGN))
def test_golden_benign(case: dict) -> None:
    result = score_candidate(_ruleset(case["tenant"]), make_candidate(case["domain"]))
    assert result.score <= case["max_score"], (
        f"{case['domain']}: {result.score} > {case['max_score']} ({case['reason']}) — {result.matched}"
    )


def test_golden_set_is_not_empty() -> None:
    # A golden set that has been emptied out would be a green test that says nothing.
    assert len(MALICIOUS) >= 6 and len(BENIGN) >= 5
