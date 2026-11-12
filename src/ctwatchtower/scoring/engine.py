"""The scoring engine (§6).

**One** function serves pipeline and UI test field: `score_candidate`. There is no
second, simplified implementation. Otherwise display and reality drift apart
(addendum §2).

Order of the formula, not negotiable (§6.2):

    raw   = Σ (weight · strength)
    raw   = max(raw, 0)
    score = raw + min(Σ combo-Boni, max_combo_bonus)
    if require_anchor and no anchor fired: score = min(score, anchor_missing_cap)
    score = clamp(score, 0, 100)

Everything adds up. There is no intermediate step where points turn into
something else. What a rule hands out ends up in the finding.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from ctwatchtower.rules.detectors import (
    detect_allowlist,
    detect_anchors,
    detect_certificate,
    detect_custom,
    detect_lures,
    detect_post_enrichment,
    detect_rules,
    detect_structure,
    detect_tlds,
    suppressed_by,
)
from ctwatchtower.rules.schema import RuleSet
from ctwatchtower.scoring.explain import (
    CandidateName,
    CertContext,
    Contribution,
    ScoreResult,
    severity_for,
)

_AGE_BUCKETS = (1, 7, 30, 90, 365)


def saturate(raw: float, k: float) -> int:
    """The old saturation curve. Nothing is scored with it any more, it only converts
    rulesets from before that change (`scripts/migrate_scoring.py`)."""
    return round(100 * (1 - math.exp(-max(raw, 0.0) / k)))


def _combo_tokens(
    contributions: list[Contribution],
    anchor_hit: bool,
    enrichment: Mapping[str, Any] | None,
    anchor_rules: frozenset[str] = frozenset(),
) -> set[str]:
    tokens: set[str] = {"anchor"} if anchor_hit else set()
    for c in contributions:
        prefix, _, rest = c.rule.partition(":")
        if prefix == "lure":
            tokens.add("lure")
        elif prefix in ("structure", "post"):
            tokens.add(rest)
        elif prefix == "tld":
            tokens.add(f"tld_group:{rest.partition(':')[0]}")
        elif prefix in ("custom", "cert"):
            tokens.add(c.rule)
        elif prefix == "rule":
            # A rule that establishes the brand reference is an anchor; any other one
            # is an extra reason, so a lure. Without that mapping a ruleset would
            # quietly lose its combo factors on migration.
            tokens.add("anchor" if c.rule in anchor_rules else "lure")
            tokens.add(c.rule)
    age = (enrichment or {}).get("domain_age_days")
    if age is not None:
        # Deliberately simple: fixed age buckets instead of an expression parser for `domain_age:<7d`.
        tokens.update(f"domain_age:<{d}d" for d in _AGE_BUCKETS if age < d)
    return tokens


def _combo_bonus(rs: RuleSet, tokens: set[str]) -> tuple[float, list[str]]:
    """Extra points for traits that mean more together than on their own."""
    bonus, applied = 0.0, []
    for combo in rs.combos:
        if set(combo.when) <= tokens:
            bonus += combo.bonus
            applied.append("+".join(combo.when))
    return min(bonus, rs.scoring.max_combo_bonus), applied


def score_candidate(
    ruleset: RuleSet,
    cand: CandidateName,
    cert: CertContext | None = None,
    enrichment: Mapping[str, Any] | None = None,
    phase: int | None = None,
) -> ScoreResult:
    """Scores a normalised name against one tenant's ruleset.

    `cert=None` is allowed (UI test field, §3 of the spec): the certificate-related
    detectors then simply do not fire. The same goes for `enrichment`. Without
    enrichment data it stays at phase 1.
    """
    sc = ruleset.scoring
    phase = phase if phase is not None else (2 if enrichment else 1)

    def result(**kw: Any) -> ScoreResult:
        return ScoreResult(
            phase=phase,
            tenant=ruleset.tenant.id,
            ruleset_hash=ruleset.ruleset_hash,
            **kw,
        )

    hit = suppressed_by(ruleset, cand)
    if hit:
        return result(
            score=0,
            severity=None,
            raw=0.0,
            combo_bonus=0.0,
            raw_effective=0.0,
            suppressed=True,
            matched=[f"allow:suppress:{hit}"],
        )

    # A rule with weight 0 must not change anything, not through a combo token and
    # not through the require_anchor cap. So it drops out completely.
    anchors = [h for h in detect_anchors(ruleset, cand) if h.weight * h.strength]
    contributions: list[Contribution] = [h.contribution() for h in anchors]
    contributions += detect_lures(ruleset, cand, anchors)
    contributions += detect_structure(ruleset, cand, anchors)
    contributions += detect_tlds(ruleset, cand)
    contributions += detect_certificate(ruleset, cand, cert, anchors)
    custom_hits = detect_custom(ruleset, cand)
    contributions += custom_hits
    rules = detect_rules(ruleset, cand)
    contributions += rules
    contributions += detect_post_enrichment(ruleset, enrichment)
    contributions += detect_allowlist(ruleset, cand)
    contributions = [c for c in contributions if c.pts]

    raw = max(sum(c.pts for c in contributions), 0.0)
    # A custom rule with `counts_as_anchor` stands in for the anchor, for brands that
    # only emerge from two words. It counts only if it actually scored points.
    anchor_rules = frozenset(
        {f"custom:{r.id}" for r in ruleset.custom if r.counts_as_anchor}
        | {f"rule:{r.name}" for r in ruleset.rules if r.counts_as_anchor}
    )
    anchored = bool(anchors) or any(c.rule in anchor_rules and c.pts for c in (*custom_hits, *rules))
    bonus, applied = _combo_bonus(
        ruleset, _combo_tokens(contributions, anchored, enrichment, anchor_rules)
    )
    raw_effective = raw + bonus

    # Points are the score. No intermediate step, no formula: what a rule hands out
    # ends up in the finding. A saturation curve used to squeeze the sum, and
    # "80 points" came out as score 86. That misled people every time they tuned a
    # ruleset. The thresholds were converted once, the severities stayed the same
    # (checked against 41 golden cases).
    score = raw_effective
    if sc.require_anchor and not anchored:
        score = min(score, sc.anchor_missing_cap)
    score = int(max(0, min(100, round(score))))

    top = sorted(contributions, key=lambda c: -abs(c.pts))[: sc.top_n]
    return result(
        score=score,
        severity=severity_for(score, ruleset.thresholds),
        raw=round(raw, 2),
        combo_bonus=round(bonus, 2),
        raw_effective=round(raw_effective, 2),
        anchor_hit=anchored,
        matched=[c.rule for c in contributions],
        contributions=top,
        combos_applied=applied,
    )
