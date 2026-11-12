"""Structural traits (§5.2 `structure`) and TLD weights (§5.2 `tlds`).

Threshold rules give strength 1.0 or nothing at all; graduated rules carry their
scale in the weight (the way the spec shows it in §6.4: `w: 24, s: 1.0`).
"""

from __future__ import annotations

import math
from collections import Counter

from ctwatchtower.rules.detectors.text import AnchorHit
from ctwatchtower.rules.schema import RuleSet
from ctwatchtower.scoring.explain import CandidateName, Contribution


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def _stem(cand: CandidateName) -> str:
    """The registrable label without the TLD (`clientportal-release` from `....cfd`)."""
    return (cand.registrable or cand.name).split(".")[0]


def detect_structure(rs: RuleSet, cand: CandidateName, anchors: list[AnchorHit]) -> list[Contribution]:
    st = rs.structure
    out: list[Contribution] = []
    name = cand.name

    if st.label_count:
        extra = len(cand.labels) - st.label_count.baseline
        if extra > 0:
            w = min(extra * st.label_count.weight_per_extra_label, st.label_count.max_weight)
            out.append(
                Contribution("structure:label_count", w=w, s=1.0,
                             detail=f"{len(cand.labels)} labels")
            )

    sub_only = [h for h in anchors if h.in_subdomain and not h.in_registrable]
    if st.brand_in_subdomain_only and sub_only:
        # The rule needs a brand and is no more certain than the brand hit itself:
        # strength = that of the strongest anchor that triggered it (§6.2).
        out.append(
            Contribution(
                "structure:brand_in_subdomain_only",
                w=st.brand_in_subdomain_only.weight,
                s=max(h.strength for h in sub_only),
                detail=", ".join(sorted(h.term for h in sub_only)),
            )
        )

    if st.hyphen_count:
        n = name.count("-")
        if n >= st.hyphen_count.threshold:
            w = min(n * st.hyphen_count.weight_per_hyphen, st.hyphen_count.max_weight)
            out.append(Contribution("structure:hyphen_count", w=w, s=1.0,
                                    detail=f"{n} hyphens"))

    if st.total_length and len(name) > st.total_length.threshold:
        over = len(name) - st.total_length.threshold
        w = min(over * st.total_length.weight_per_char, st.total_length.max_weight)
        out.append(Contribution("structure:total_length", w=w, s=1.0,
                                detail=f"{len(name)} characters"))

    if st.digit_ratio:
        stem = _stem(cand)
        ratio = sum(c.isdigit() for c in stem) / len(stem) if stem else 0.0
        if ratio > st.digit_ratio.threshold:
            out.append(
                Contribution("structure:digit_ratio", w=st.digit_ratio.weight, s=1.0, detail=f"{ratio:.2f}")
            )

    if st.shannon_entropy:
        h = shannon_entropy(_stem(cand))
        if h > st.shannon_entropy.threshold:
            out.append(
                Contribution(
                    "structure:shannon_entropy", w=st.shannon_entropy.weight, s=1.0, detail=f"{h:.2f}"
                )
            )

    if st.punycode:
        is_puny = cand.is_idn or "xn--" in cand.ascii.lower()
        if is_puny and (anchors or not st.punycode.only_if_anchor_matched):
            out.append(Contribution("structure:punycode", w=st.punycode.weight, s=1.0, detail=cand.ascii))

    if st.numeric_lookalike:
        # Deliberately simple: digit substitution = a digit in the name plus an
        # anchor hit that only came about via skeleton or permutation. Enough for
        # paypa1/sparkass3; a finer positional analysis once that produces FPs.
        digits = any(c.isdigit() for c in _stem(cand))
        via_lookalike = any(h.type in ("homoglyph", "permutation") for h in anchors)
        if digits and via_lookalike:
            out.append(Contribution("structure:numeric_lookalike", w=st.numeric_lookalike.weight, s=1.0))

    return out


def _tld_forms(tld: str) -> tuple[str, ...]:
    """A multi-part suffix also matches on its last label.

    `cand.tld` carries the full public suffix (`co.uk`), but the spec's rule lists
    hold single labels (`uk`, `br`, `in`, `tw` in §5.2). Without this widening an
    entry `uk` would quietly never fire for `.co.uk`.
    """
    return (tld, tld.rsplit(".", 1)[-1]) if "." in tld else (tld,)


def detect_tlds(rs: RuleSet, cand: CandidateName) -> list[Contribution]:
    tld = (cand.tld or "").lower()
    if not tld:
        return []
    forms = _tld_forms(tld)
    for override in rs.tlds.overrides:
        if any(f in override.tld for f in forms):
            return [Contribution(f"tld:override:{tld}", w=override.weight, s=1.0)]
    for group in rs.tlds.groups:
        if any(f in group.list_ for f in forms):
            return [Contribution(f"tld:{group.name}:{tld}", w=group.weight, s=1.0)]
    if rs.tlds.default_weight:
        return [Contribution(f"tld:default:{tld}", w=rs.tlds.default_weight, s=1.0)]
    return []
