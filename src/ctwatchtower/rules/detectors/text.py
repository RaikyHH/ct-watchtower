"""Text detectors: anchors, lure terms, custom regex rules.

strength values follow the table in §6.2. Exact 1.0, homoglyph 0.95, permutation
0.9, fuzzy `1 - d/(max_d+1)`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

from rapidfuzz.distance import DamerauLevenshtein

from ctwatchtower.rules.schema import MIN_TERM_LENGTH, MatchSpec, Rule, RuleSet
from ctwatchtower.scoring.explain import CandidateName, Contribution

EXACT, HOMOGLYPH, PERMUTATION, FUZZY = "exact", "homoglyph", "permutation", "fuzzy"
# Separators INSIDE a label only. The dot stays: take it out and you get words
# nobody ever wrote, `fastbank.database.de` turns into `fastbankdatabase`, and
# that suddenly contains the anchor "bankdata". On the live stream that was the
# reason for hits on names with no brand reference at all.
_SEPARATORS = str.maketrans("", "", "-_")
# For comparing a single label with a short term; no dot can occur there anyway.
_LABEL_SEPARATORS = _SEPARATORS
_TOKEN_SPLIT = re.compile(r"[.\-_]+")


@dataclass(slots=True)
class AnchorHit:
    term: str
    type: str
    strength: float
    weight: float
    in_registrable: bool = False
    in_subdomain: bool = False
    also: list[str] = field(default_factory=list)  # other terms of the same group
    # Spans: (text found, in the skeleton?). For the lure exclusion (§5.2 lures)
    spans: list[tuple[str, bool]] = field(default_factory=list)

    def contribution(self) -> Contribution:
        detail = f"also: {', '.join(self.also)}" if self.also else None
        return Contribution(
            rule=f"anchor:{self.term}", w=self.weight, s=self.strength, type=self.type, detail=detail
        )


def _forms(text: str) -> tuple[str, str]:
    """The raw form and the form without hyphens and underscores.

    The latter catches the separator trick (`d-a-t-a-p-o-r-t`, §4.2). Dots stay: a
    dot separates two names that have nothing to do with each other, and pulling
    them together invents hits across the label boundary.
    """
    low = text.lower()
    return low, low.translate(_SEPARATORS)


def _contains(term: str, text: str) -> bool:
    plain, dotless = _forms(text)
    return term in plain or term in dotless


def _tokens(text: str) -> list[str]:
    """Labels and their parts at `.`, `-`, `_`. The units an attacker registers or
    puts together (`paypa1-secure.login.top` -> `paypa1`, `secure` and so on)."""
    low = text.lower()
    labels = [label for label in low.split(".") if label]
    return list(dict.fromkeys([*labels, *(t for t in _TOKEN_SPLIT.split(low) if t)]))


def _anchor_in(term: str, text: str) -> bool:
    """Anchor term in `text`. Short terms (< MIN_TERM_LENGTH) only as a whole token
    or as a separator-free label (`z-e-l-o`): `vexa` in `venexamultimarcas` and `oria`
    in `groups` are not a brand.

    Deliberately simple: `temushop.de` falls through. Whoever needs that enters
    `temushop` as a term of its own. An explicit rule instead of a substring
    heuristic."""
    if len(term) >= MIN_TERM_LENGTH:
        return _contains(term, text)
    labels = text.lower().split(".")
    return term in _tokens(text) or any(label.translate(_LABEL_SEPARATORS) == term for label in labels)


def _fuzzy_strength(term: str, labels: list[str], max_distance: int, uncapped: bool) -> tuple[float, str]:
    """strength `1 - d/(max_d+1)` (§6.2). Only a quarter of the term length is
    allowed though, at least 1: two edits on `payro` are 40 % of the brand
    (`payroll`, `cluster` -> `stellax`, `vaulted` -> `northvault` in the sample).
    `uncapped` (`fuzzy.allow_distance_above_quarter`) lifts that per group."""
    allowed = max_distance if uncapped else min(max_distance, max(1, len(term) // 4))
    best, found = 0.0, ""
    for label in labels:
        if abs(len(label) - len(term)) > allowed:
            continue
        d = DamerauLevenshtein.distance(term, label, score_cutoff=allowed)
        if d == 0 or d > allowed:
            continue  # d == 0 is an exact hit, EXACT covers that
        s = 1 - d / (max_distance + 1)
        if s > best:
            best, found = s, label
    return best, found


def _zone_skeletons(cand: CandidateName) -> tuple[str, str]:
    """The skeleton split into registrable part and subdomain.

    Deliberately simple: matched up by label count. Skeleton rules like `rn -> m`
    can change the length but not the number of dots; if the label counts differ
    anyway, the whole skeleton applies to both zones (better one hit too many than
    one too few).
    """
    sk_labels = cand.skeleton.split(".")
    if len(sk_labels) != len(cand.labels):
        return cand.skeleton, cand.skeleton
    n_reg = len(cand.registrable.split(".")) if cand.registrable else 2
    return ".".join(sk_labels[-n_reg:]), ".".join(sk_labels[:-n_reg])


_Match = tuple[str, float, tuple[str, bool] | None]  # kind, strength, span
_NO_MATCH: _Match = ("", 0.0, None)


def _best_in_zone(
    term: str, m: MatchSpec, exclude: list[str], rs: RuleSet, zone: str, zone_skeleton: str
) -> _Match:
    """The strongest hit for `term` in one zone. Knows no group, only the match spec
    and the exceptions. That way one function serves anchors and rules alike."""
    for word in exclude:
        zone, zone_skeleton = zone.replace(word, "."), zone_skeleton.replace(word, ".")
    if not zone.strip("."):
        return _NO_MATCH
    if m.exact and _anchor_in(term, zone):
        return EXACT, 1.0, (term, False)
    if m.homoglyph and zone_skeleton and _anchor_in(term, zone_skeleton):
        return HOMOGLYPH, 0.95, (term, True)
    pattern = rs.permutation_patterns.get(term) if m.permutations.enabled else None
    # Only as a whole token and only as it is written: separator variants are
    # generated by `hyphenation` itself, and via the separator-free form `hemes`
    # (korvex) would be found straight across `blithe-mesa`.
    found = pattern.search(zone.lower()) if pattern else None
    if found:
        return PERMUTATION, 0.9, (found.group(1), False)
    if m.fuzzy.enabled and len(term) >= m.fuzzy.min_term_length:
        s, token = _fuzzy_strength(
            term, _tokens(zone), m.fuzzy.max_distance, m.fuzzy.allow_distance_above_quarter
        )
        if s > 0:
            return FUZZY, round(s, 4), (token, False)
    return _NO_MATCH


def detect_anchors(rs: RuleSet, cand: CandidateName) -> list[AnchorHit]:
    """One hit per anchor group: the group carries a weight, so it is one signal.

    The strongest term of the group counts (`mycompany` before `my-company`), the
    others go into `also`. The same term in two groups (an include plus the own
    file) counts once, with the stronger group.
    """
    reg_skeleton, sub_skeleton = _zone_skeletons(cand)
    hits: dict[str, AnchorHit] = {}
    for group in rs.anchors:
        if cand.registrable in group.owned_domains:
            continue  # name under a domain of the brand: their own infrastructure
        group_hits: list[AnchorHit] = []
        for term in group.terms:
            reg_type, reg_s, reg_span = _best_in_zone(
                term, group.match, group.exclude, rs, cand.registrable, reg_skeleton
            )
            sub_type, sub_s, sub_span = _best_in_zone(
                term, group.match, group.exclude, rs, cand.subdomain, sub_skeleton
            )
            if not reg_s and not sub_s:
                continue
            type_, strength = (reg_type, reg_s) if reg_s >= sub_s else (sub_type, sub_s)
            group_hits.append(
                AnchorHit(
                    term=term,
                    type=type_,
                    strength=strength,
                    weight=group.weight,
                    in_registrable=reg_s > 0,
                    in_subdomain=sub_s > 0,
                    spans=[span for span in (reg_span, sub_span) if span],
                )
            )
        if not group_hits:
            continue
        best = max(group_hits, key=lambda h: h.strength)  # on a tie, the first one
        best.also = [h.term for h in group_hits if h is not best]
        best.spans = [span for h in group_hits for span in h.spans]
        previous = hits.get(best.term)
        if previous is None or best.strength * best.weight > previous.strength * previous.weight:
            hits[best.term] = best
    return list(hits.values())


@lru_cache(maxsize=512)
def _without_separators(hay: str) -> tuple[str, tuple[int, ...]]:
    """The name without separators, plus the mapping back to the positions.

    Belongs computed once per name, not once per search term. `_occurrences` used
    to build it again for each of the forty lure terms, which came to 1.45 million
    string builds over 15,000 scorings. The cache is small: within one scoring only
    a handful of different strings turn up (name, skeleton, zones).
    """
    idx = tuple(i for i, ch in enumerate(hay) if ch not in ".-_")
    return "".join(hay[i] for i in idx), idx


def _occurrences(needle: str, hay: str, whole_word: bool = False) -> list[tuple[int, int]]:
    """Every occurrence of `needle` in `hay` and in its separator-free form, as
    (inclusive) position ranges in `hay`.

    `whole_word` keeps only occurrences with no letter next to them left or right:
    `bridge` then matches in `bridge-login.de` and `login.bridge.de` but not in
    `bridgeintelligence.com`. Dot, hyphen, underscore and digits count as a word
    boundary. In domain names those are exactly what separates the words.
    """
    dotless, idx = _without_separators(hay)
    out = []
    for text, pos in ((hay, range(len(hay))), (dotless, idx)):
        start = text.find(needle)
        while start != -1:
            out.append((pos[start], pos[start + len(needle) - 1]))
            start = text.find(needle, start + 1)
    if not whole_word:
        return out
    return [(a, b) for a, b in out if not _touches_letter(hay, a, b)]


def _touches_letter(hay: str, start: int, end: int) -> bool:
    before = hay[start - 1] if start > 0 else ""
    after = hay[end + 1] if end + 1 < len(hay) else ""
    return before.isalpha() or after.isalpha()


def _anchor_ranges(cand: CandidateName, anchors: list[AnchorHit]) -> list[tuple[int, int]]:
    name, skeleton = cand.name.lower(), cand.skeleton.lower()
    ranges = []
    for hit in anchors:
        for text, in_skeleton in hit.spans:
            # Deliberately simple: skeleton spans only when the skeleton has the
            # same length (then the positions line up); `rn -> m` shifts them, and
            # there the lure counts in case of doubt.
            if in_skeleton and len(skeleton) != len(name):
                continue
            ranges += _occurrences(text, skeleton if in_skeleton else name)
    return ranges


def detect_lures(rs: RuleSet, cand: CandidateName, anchors: list[AnchorHit]) -> list[Contribution]:
    """Lure terms. A lure whose span sits entirely inside the span of an anchor or
    of a longer lure does not count: `mein` in `meinefirma` is the brand, `sicher`
    in `securitydesk` is already the lure `securitydesk`."""
    out: list[Contribution] = []
    seen: set[str] = set()
    name = cand.name.lower()
    anchor_ranges = _anchor_ranges(cand, anchors)

    # Keep only terms that occur at all. A lure without a span contributes nothing,
    # neither for itself nor to another term's "longer" set.
    found: dict[str, list[tuple[int, int]]] = {}
    for group in rs.lures:
        for term in group.terms:
            if term not in found and (occ := _occurrences(term, name)):
                found[term] = occ

    # The spans of longer lures, layered by length once instead of collected again
    # for every term. This used to be quadratic in the number of lure terms and at
    # 40 terms made up the lion's share of the whole scoring time (measured: 71 %
    # of the runtime, 163 million `len` calls over 15,000 scorings).
    longer: dict[str, list[tuple[int, int]]] = {}
    piled_up: list[tuple[int, int]] = []
    for length in sorted({len(t) for t in found}, reverse=True):
        same_length = [t for t in found if len(t) == length]
        for term in same_length:
            longer[term] = piled_up
        piled_up = piled_up + [r for term in same_length for r in found[term]]

    def free(term: str) -> bool:
        ranges = anchor_ranges + longer[term]
        return any(not any(a <= start and end <= b for a, b in ranges) for start, end in found[term])

    for group in rs.lures:
        for term in group.terms:
            if term in seen or term not in found or not free(term):
                continue
            # `whole_word` narrows the lure down to standalone words. Meant for
            # short everyday words: `bridge` sits in `bridgeintelligence` without
            # anybody being lured there.
            if group.whole_word and not _occurrences(term, name, whole_word=True):
                continue
            seen.add(term)
            out.append(Contribution(rule=f"lure:{term}", w=group.weight, s=1.0, type=EXACT))
    return out


def detect_custom(rs: RuleSet, cand: CandidateName) -> list[Contribution]:
    out: list[Contribution] = []
    for rule in rs.custom:
        plain, dotless = _forms(cand.name)
        if re.search(rule.regex, plain) or re.search(rule.regex, dotless):
            out.append(Contribution(rule=f"custom:{rule.id}", w=rule.weight, s=1.0, detail=rule.description))
    return out


# ------------------------- Rules (AND/OR) -------------------------


def _line_matches(
    rule: Rule, condition, rs: RuleSet, cand: CandidateName, skeletons: tuple[str, str]
) -> tuple[float, str]:
    """The strongest hit of one line (the terms in it are OR-joined).

    Returns `(strength, term found)`, or `(0.0, "")`. A pattern matches at full
    strength or not at all. It says itself what it allows, so it is never fuzzed on
    top of that.
    """
    reg_skeleton, sub_skeleton = skeletons
    plain, dotless = _forms(cand.name)
    best, found = 0.0, ""
    for term in condition.any_of:
        if term.pattern:
            pattern = rs.rule_patterns.get(term.text)
            if pattern and (pattern.search(plain) or pattern.search(dotless)):
                return 1.0, term.text
            continue
        m = rule.match_for(term.text)
        _, reg_s, _ = _best_in_zone(term.text, m, rule.exclude, rs, cand.registrable, reg_skeleton)
        _, sub_s, _ = _best_in_zone(term.text, m, rule.exclude, rs, cand.subdomain, sub_skeleton)
        s = max(reg_s, sub_s)
        if s > best:
            best, found = s, term.text
    return best, found


def detect_rules(rs: RuleSet, cand: CandidateName) -> list[Contribution]:
    """A rule matches when **every** one of its lines matches (§6.2, extension).

    The strength is that of the weakest line: a chain is as strong as its weakest
    link. A negated line contributes full strength, it is satisfied by absence, not
    by a weak hit.
    """
    skeletons = _zone_skeletons(cand)
    out: list[Contribution] = []
    for rule in rs.rules:
        if cand.registrable in rule.owned_domains:
            continue  # name under one of the brand's own domains
        weakest, evidence = 1.0, []
        for condition in rule.all_of:
            strength, term = _line_matches(rule, condition, rs, cand, skeletons)
            if condition.negate:
                if strength:
                    break  # forbidden and there anyway: the rule does not match
                continue
            if not strength:
                break
            weakest = min(weakest, strength)
            evidence.append(term)
        else:
            out.append(
                Contribution(
                    rule=f"rule:{rule.name}",
                    w=rule.weight,
                    s=round(weakest, 4),
                    detail=" + ".join(evidence) or None,
                )
            )
    return out
