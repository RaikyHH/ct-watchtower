"""Pydantic model of a ruleset (specification §5.2, §6.3).

Every node inherits from `Node`: `description` is allowed everywhere (the spec uses
it as inline documentation), everything else is `extra="forbid"`, because a typo in
a rule file should show up at load time instead of being ignored.
"""

from __future__ import annotations

import functools
import hashlib
import re
import time

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PERMUTATION_KINDS = (
    "omission",
    "insertion",
    "transposition",
    "replacement",
    "hyphenation",
    "bitsquatting",
    "vowel_swap",
    "repetition",
    "double_char",
    "tld_swap",
)

# Engine default (the spec finance example says `min_term_length: 5`): shorter terms
# get neither fuzzy nor permutations, and their exact hits only count as a whole
# token. Four letters with two allowed edits are half the brand (`zelo` vs `duzel`).
MIN_TERM_LENGTH = 5


class Node(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    description: str | None = None


class Sourced(Node):
    """A group whose source file the loader records (anchors, lures, TLDs).

    `source` is read-only: the loader sets it *after* validation and `model_dump()`
    hands it to the UI. A `source` sent in (a form that plays the API answer back)
    is dropped on input, never an error, and never part of `ruleset_hash` or the
    score.
    """

    source: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _drop_source(cls, data: object) -> object:
        if isinstance(data, dict) and "source" in data:
            data = {k: v for k, v in data.items() if k != "source"}
        return data


# Paths of the `Sourced` groups. For `ruleset_hash` and `drop_source`.
_NO_SOURCE = {
    "anchors": {"__all__": {"source"}},
    "lures": {"__all__": {"source"}},
    "tlds": {"groups": {"__all__": {"source"}}},
}


def raw_groups(doc: dict) -> list:
    """The `Sourced` groups of a raw document, in model order: anchors, lures,
    TLD groups."""
    tlds = doc.get("tlds")
    return [
        *(doc.get("anchors") or []),
        *(doc.get("lures") or []),
        *((tlds.get("groups") or []) if isinstance(tlds, dict) else []),
    ]


def drop_source(doc: dict) -> dict:
    """Strip `source` from a raw rule document before it goes into a YAML file.

    For write paths that put the raw document back (not `model_dump()`). Changes
    `doc` in place and returns it.
    """
    for group in raw_groups(doc):
        if isinstance(group, dict):
            group.pop("source", None)
    return doc


def _lower(values: list[str]) -> list[str]:
    return [v.strip().lower() for v in values if v and v.strip()]


# --------------------------------- Head ---------------------------------


class Tenant(Node):
    id: str = Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$")
    name: str
    enabled: bool = True
    tlp: str = "clear"

    @field_validator("id")
    @classmethod
    def _not_reserved(cls, v: str) -> str:
        """The ids of the pseudo tenants are taken.

        They sit in the tenant picker and would otherwise show up twice there:
        once as the collected view, once as a real tenant.
        """
        from ctwatchtower.pseudo_tenants import PSEUDO

        if v in PSEUDO:
            raise ValueError(
                f"`{v}` is taken by the {PSEUDO[v]!r} view "
                f"and cannot be a tenant")
        return v


class Thresholds(Node):
    # Points, not percent. The values are the old defaults converted (saturation
    # scale 35/45/60/80 at k=40). Set nothing and you get the same severities as
    # before.
    persist: float = 17
    info: float = 24
    warning: float = 37
    alert: float = 64
    enrich_from: float = 28
    feed_from: float = 37


class Scoring(Node):
    require_anchor: bool = True
    anchor_missing_cap: float = 9  # converted from the former 20 score points
    max_combo_bonus: float = Field(40, ge=0)  # cap across all combinations
    top_n: int = Field(12, ge=1)


# -------------------------------- Anchors --------------------------------


class Fuzzy(Node):
    enabled: bool = False
    max_distance: int = Field(2, ge=1, le=4)
    min_term_length: int = Field(MIN_TERM_LENGTH, ge=1)
    # The engine allows at most a quarter of the term length as distance (at least
    # 1). `true` lifts that for this group, and `max_distance` alone applies.
    allow_distance_above_quarter: bool = False


class Permutations(Node):
    enabled: bool = False
    kinds: list[str] = list(PERMUTATION_KINDS)
    min_term_length: int = Field(MIN_TERM_LENGTH, ge=1)

    @field_validator("kinds")
    @classmethod
    def _known(cls, kinds: list[str]) -> list[str]:
        unknown = sorted(set(kinds) - set(PERMUTATION_KINDS))
        if unknown:
            raise ValueError(f"unknown permutation kind(s): {', '.join(unknown)}")
        return kinds


class MatchSpec(Node):
    exact: bool = True
    homoglyph: bool = False
    fuzzy: Fuzzy = Fuzzy()
    permutations: Permutations = Permutations()


class AnchorGroup(Sourced):
    terms: list[str] = Field(min_length=1)
    weight: float
    match: MatchSpec = MatchSpec()
    # Words that look like a variant of the brand but are not (`stellax` vs
    # `stellar`, `payro` vs `payroll`). They are cut out of the name before this
    # group is matched. A visible list instead of a dictionary heuristic.
    exclude: list[str] = []
    # Registrable domains that belong to the brands of this group themselves
    # (`amazonaws.com`). If a name sits under one, this group's anchor counts
    # nowhere in the name; anchors of other groups still do
    # (`paylio-login.s3.amazonaws.com`).
    owned_domains: list[str] = []

    @field_validator("terms", "exclude", "owned_domains")
    @classmethod
    def _low(cls, v: list[str]) -> list[str]:
        return _lower(v)


PATTERN_MAX_LENGTH = 200
PATTERN_TIME_BUDGET = 0.01  # seconds for a single sample
# Growing samples in small steps. The step size matters: backtracking grows
# exponentially, so one step costs at most a base to the fourth, which keeps even
# the sample that blows the budget in the range of fractions of a second. A domain
# label is at most 63 characters, 48 is close enough to the worst case.
PATTERN_SAMPLE_LENGTHS = range(8, 49, 4)
# A quantifier that contains a quantifier: `(a+)+`, `(a*)*`, `([a-z]+)*`. That is
# exactly what produces exponential backtracking.
_NESTED_QUANTIFIER = re.compile(
    r"\((?:[^()\\]|\\.)*[*+}][^()]*\)\s*(?:[*+]|\{\d)"
)
_SAMPLE_PATTERNS = ("a", "ab", "a-", "0", "a.")


def check_pattern(pattern: str) -> re.Pattern[str]:
    """Check a hand-written pattern before it may go into the pipeline.

    The patterns run for every certificate that gets past the prefilter, a few
    thousand a second. An expression like `(a+)+b` backtracks exponentially and
    stalls the scorer. Python regex has no time limit, so the check has to happen
    here, on save, where a slow expression only holds up whoever saves it.

    Three bounds: length, nested quantifiers, measured runtime on growing samples.
    The samples grow in steps of four and stop as soon as a single one is over
    budget. Anything that backtracks exponentially shows up there before the check
    itself takes long.

    The limit of this check, frankly: it catches accidents, not attacks. Build a
    pattern that only blows up at 60 characters and it gets through. But the
    patterns are written by whoever runs the application, and whoever stalls their
    own pipeline notices. Against a determined attacker only moving the evaluation
    into its own process with a time limit would help.
    """
    if len(pattern) > PATTERN_MAX_LENGTH:
        raise ValueError(
            f"pattern is too long ({len(pattern)} characters, {PATTERN_MAX_LENGTH} allowed)")
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"pattern does not compile: {exc}") from exc
    if _NESTED_QUANTIFIER.search(pattern):
        raise ValueError(
            "pattern has a quantifier inside a quantifier (like `(a+)+`). That can keep "
            "the evaluation busy for an exponential time, so it is not allowed."
        )
    # The samples have to fit the pattern, otherwise it is done at once without ever
    # backtracking: `(x|xx|xxx)+y` does not get stuck on a row of "a". So the
    # pattern's own letters are added.
    own = list(dict.fromkeys(re.findall(r"[a-z0-9]", pattern.lower())))[:6]
    pieces = (*_SAMPLE_PATTERNS, *own)
    for length in PATTERN_SAMPLE_LENGTHS:
        for piece in pieces:
            # Without and with a trailing foreign character: the latter forces the
            # backtracking that makes the difference (`(a|aa)+b` against a row of a).
            for sample in (piece * length, piece * length + "!"):
                start = time.perf_counter()
                compiled.search(sample[: length + 1])
                if time.perf_counter() - start > PATTERN_TIME_BUDGET:
                    raise ValueError(
                        f"pattern already takes too long at {length} characters. An "
                        "expression like that would hold up the certificate stream."
                    )
    return compiled


# ------------------------- Rules (AND/OR) -------------------------
#
# A rule is: a name, a number of points, a condition. Three levels, no nesting.
# That covers every case tuning a ruleset against the live stream has asked for,
# and it stays explainable in one sentence:
#
#   terms in one line    -> OR
#   lines below each other -> AND
#   rules next to each other -> add their points
#
# `anchors` and `lures` are the special case "a single line"; they stay valid
# because the bundled building blocks hang off them.

# How many edits a term tolerates from which length on. Measured on the live
# stream: two edits at eight letters matched `datanorte` for an eight-letter brand
# name. Whoever needs it differently sets `match` explicitly.
TOLERANCE_STEPS = ((10, 2), (5, 1))


class Term(Node):
    """One entry in a line: a word or a pattern.

    In the YAML a word is simply a string; a pattern is `{pattern: "..."}`. A
    pattern is never fuzzed, it already says itself what it allows.
    """

    text: str = Field(min_length=1)
    pattern: bool = False

    @model_validator(mode="before")
    @classmethod
    def _from_string(cls, value):
        if isinstance(value, str):
            return {"text": value.lower(), "pattern": False}
        if isinstance(value, dict) and "pattern" in value and isinstance(value["pattern"], str):
            return {"text": value["pattern"], "pattern": True}
        return value

    @model_validator(mode="after")
    def _pattern_compiles(self):
        if self.pattern:
            check_pattern(self.text)
        return self


class Condition(Node):
    """One line: one of these terms has to occur, or none of them (`negate`)."""

    any_of: list[Term] = Field(min_length=1)
    negate: bool = False


class Rule(Sourced):
    name: str = Field(min_length=1)
    weight: float
    all_of: list[Condition] = Field(min_length=1)
    # Establishes the brand reference: without such a rule a finding stays below
    # `anchor_missing_cap`. Not everything being watched has a brand name; a public
    # authority is only recognisable from two words next to each other.
    counts_as_anchor: bool = False
    # Catch spelling variants: typos, digits for letters, confusable characters,
    # separator tricks. Off means: spelled exactly like this.
    tolerant: bool = True
    # An explicitly set match spec beats `tolerant`, for rulesets that were taken
    # over from `anchors` and should keep their setting.
    match: MatchSpec | None = None
    exclude: list[str] = []
    owned_domains: list[str] = []

    @field_validator("exclude", "owned_domains")
    @classmethod
    def _low(cls, v: list[str]) -> list[str]:
        return _lower(v)

    @property
    def words(self) -> list[str]:
        """All words (no patterns) across all lines, the negated ones too.

        For the permutations: if "amtsportal" is forbidden, `amtsportl` should
        block the rule as well. This list is no good for the prefilter, though.
        """
        return [t.text for c in self.all_of for t in c.any_of if not t.pattern]

    @property
    def prefilter_words(self) -> list[str]:
        """Only words from required lines.

        A negated word does not belong in the prefilter: the rule asks for it
        **not** to occur. Take it in and an everyday word like "login" from an
        exclusion line would pull half the certificate stream through the
        automaton.
        """
        return [t.text for c in self.all_of if not c.negate for t in c.any_of if not t.pattern]

    def match_for(self, term: str) -> MatchSpec:
        """The match spec for exactly this term.

        How wide the typo matching goes depends on the word length, not on a
        setting: that is the value that otherwise sits too wide every time.
        """
        if self.match is not None:
            return self.match
        if not self.tolerant:
            return MatchSpec(exact=True)
        distance = next((d for length, d in TOLERANCE_STEPS if len(term) >= length), 0)
        return MatchSpec(
            exact=True,
            homoglyph=True,
            permutations=Permutations(enabled=True),
            fuzzy=Fuzzy(enabled=distance > 0, max_distance=max(distance, 1)) if distance else Fuzzy(),
        )


class LureGroup(Sourced):
    terms: list[str] = Field(min_length=1)
    weight: float
    # Count only as a standalone word (`bridge` not in `bridgeintelligence`).
    # Off: a lure matches anywhere in the name. That is still the default, because
    # phishing domains like to run words together (`loginportal`).
    whole_word: bool = False

    @field_validator("terms")
    @classmethod
    def _low(cls, v: list[str]) -> list[str]:
        return _lower(v)


# ------------------------ Structural traits ------------------------


class LabelCount(Node):
    baseline: int = 2
    weight_per_extra_label: float = 8
    max_weight: float = 32


class Weighted(Node):
    weight: float


class HyphenCount(Node):
    threshold: int = 2
    weight_per_hyphen: float = 5
    max_weight: float = 20


class TotalLength(Node):
    threshold: int = 25
    weight_per_char: float = 0.5
    max_weight: float = 15


class Threshold(Node):
    threshold: float
    weight: float


class Punycode(Node):
    weight: float
    only_if_anchor_matched: bool = True


class Structure(Node):
    label_count: LabelCount | None = None
    brand_in_subdomain_only: Weighted | None = None
    hyphen_count: HyphenCount | None = None
    total_length: TotalLength | None = None
    digit_ratio: Threshold | None = None
    shannon_entropy: Threshold | None = None
    punycode: Punycode | None = None
    numeric_lookalike: Weighted | None = None


# ---------------------------------- TLDs ---------------------------------


class TldGroup(Sourced):
    name: str
    weight: float
    list_: list[str] = Field(alias="list")

    @field_validator("list_")
    @classmethod
    def _low(cls, v: list[str]) -> list[str]:
        return _lower(v)


class TldOverride(Node):
    tld: list[str]
    weight: float

    @field_validator("tld")
    @classmethod
    def _low(cls, v: list[str]) -> list[str]:
        return _lower(v)


class Tlds(Node):
    groups: list[TldGroup] = []
    default_weight: float = 0
    overrides: list[TldOverride] = []


# ----------------------- Certificate traits ----------------------


class ValidityDays(Node):
    enabled: bool = False
    max_days: int | None = None
    min_days: int | None = None
    weight: float = 0


class SanBrandFanout(Node):
    min_matching_sans: int = 3
    weight: float


class IssuerGroup(Node):
    name: str
    weight: float
    match: list[str] = []
    match_ev: bool = False


class Certificate(Node):
    san_count: Threshold | None = None
    san_brand_fanout: SanBrandFanout | None = None
    validity_days: ValidityDays | None = None
    issuer_groups: list[IssuerGroup] = []


# --------------- Downstream (after enrichment) ---------------


class DomainAgeRule(Node):
    max_age_days: int | None = None
    min_age_days: int | None = None
    weight: float


class ListRule(Node):
    weight: float
    # Path relative to the repository, e.g. `data/registrar_brand_protection.yaml`.
    list_file: str | None = None


class RegexRule(Node):
    weight: float
    regex: list[str] = []


class PostEnrichment(Node):
    domain_age: list[DomainAgeRule] = []
    privacy_registrar: ListRule | None = None
    # Brand protection registrar (MarkMonitor, CSC and the like): the domain very
    # likely belongs to a company protecting its brands. Meant as a negative weight.
    brand_protection_registrar: ListRule | None = None
    nameserver_patterns: RegexRule | None = None
    no_resolution: Weighted | None = None
    parking_detected: Weighted | None = None


# ----------- Custom rules, exceptions, combinations ----------


class CustomRule(Node):
    id: str
    regex: str
    weight: float
    # An anchor is otherwise always a single term. Some brands have none, though: a
    # public authority is recognised by "citizen service *next to* the place name",
    # not by either word on its own. The place name alone reports every driving
    # school in town. Rules like that lift `anchor_missing_cap` with this switch
    # instead of suffocating under it. Without it everything stays as it was.
    counts_as_anchor: bool = False


class MatchPatterns(Node):
    exact: list[str] = []
    suffix: list[str] = []
    regex: list[str] = []

    @field_validator("exact", "suffix")
    @classmethod
    def _low(cls, v: list[str]) -> list[str]:
        return _lower(v)


class Downweight(Node):
    match: MatchPatterns
    weight: float
    note: str | None = None


class Allowlist(Node):
    suppress: MatchPatterns = MatchPatterns()
    downweight: list[Downweight] = []


class Combo(Node):
    # Points, not multipliers: `bonus` is added like any other weight. A factor
    # depended on whatever else happened to hit, so the same combination was worth
    # 9 points once and 30 the next time.
    when: list[str] = Field(min_length=1)
    bonus: float = Field(ge=0)


class Notification(Node):
    channel: str
    target: str
    min_severity: str = "warning"
    aggregate_window: int | None = None


# -------------------------------- RuleSet --------------------------------


class RuleSet(Node):
    # v1 = thresholds on the saturation scale, v2 = thresholds in points. The loader
    # rejects v1 instead of quietly scoring wrong.
    apiVersion: str = "ctwatchtower/v2"
    kind: str = "RuleSet"
    includes: list[str] = []
    shadow: bool = False

    tenant: Tenant
    thresholds: Thresholds = Thresholds()
    scoring: Scoring = Scoring()
    anchors: list[AnchorGroup] = []
    lures: list[LureGroup] = []
    structure: Structure = Structure()
    tlds: Tlds = Tlds()
    certificate: Certificate = Certificate()
    post_enrichment: PostEnrichment = PostEnrichment()
    rules: list[Rule] = []
    custom: list[CustomRule] = []
    allowlist: Allowlist = Allowlist()
    combos: list[Combo] = []
    notifications: list[Notification] = []

    @functools.cached_property
    def ruleset_hash(self) -> str:
        """Fingerprint of the validated ruleset. A finding can point to the rule
        version that produced it. `source` does not count: the same rules from a
        different file are the same rule version."""
        payload = self.model_dump_json(by_alias=True, exclude=_NO_SOURCE)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    @functools.cached_property
    def anchor_terms(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(t for g in self.anchors for t in g.terms))

    @functools.cached_property
    def permutation_index(self) -> dict[str, frozenset[str]]:
        """Anchor term -> typo variants generated at load time (§4.2 stage 1)."""
        from ctwatchtower.rules.permutations import permutations_for

        out: dict[str, set[str]] = {}
        for group in self.anchors:
            if not group.match.permutations.enabled:
                continue
            perm = group.match.permutations
            for term in group.terms:
                variants = permutations_for(term, perm.kinds, perm.min_term_length)
                out.setdefault(term, set()).update(variants - set(group.exclude))
        for rule in self.rules:
            for word in rule.words:
                perm = rule.match_for(word).permutations
                if not perm.enabled:
                    continue
                variants = permutations_for(word, perm.kinds, perm.min_term_length)
                out.setdefault(word, set()).update(variants - set(rule.exclude))
        return {term: frozenset(v - {term}) for term, v in out.items()}

    @functools.cached_property
    def rule_patterns(self) -> dict[str, re.Pattern[str]]:
        """Compiled patterns from the rules. Checked and compiled once at load time,
        so the scorer does not compile again for every certificate."""
        return {
            term.text: check_pattern(term.text)
            for rule in self.rules
            for condition in rule.all_of
            for term in condition.any_of
            if term.pattern
        }

    @functools.cached_property
    def rules_without_prefilter(self) -> tuple[str, ...]:
        """Rules the prefilter cannot reach: they have no word in any required line,
        only patterns.

        The prefilter (§4.2) is an automaton over words; what does not go in there
        is never scored. Rules like that only take effect for names that were let
        through because of another rule. The UI warns about them.
        """
        return tuple(
            rule.name
            for rule in self.rules
            if not any(
                any(not t.pattern for t in condition.any_of)
                for condition in rule.all_of
                if not condition.negate
            )
        )

    @functools.cached_property
    def permutation_patterns(self) -> dict[str, re.Pattern[str]]:
        """One alternation of its variants per term, only at token boundaries (start
        or end, or `.`, `-`, `_`). dnstwist variants are whole names; as a substring
        `tellax` (stellax) sits in `constellation` and `payro` in `payroll`.
        Longest variant first, so the match covers the whole variant."""
        return {
            term: re.compile(
                rf"(?<![a-z0-9])({'|'.join(map(re.escape, sorted(v, key=len, reverse=True)))})(?![a-z0-9])"
            )
            for term, v in self.permutation_index.items()
            if v
        }
