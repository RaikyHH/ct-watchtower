"""Explain a ruleset in sentences.

Server side and from the **validated** model, not rebuilt in the browser: otherwise
explanation and reality drift apart as soon as somebody changes a default. The same
function can later explain in the finding detail why a finding came about.

The output is structured, not a finished string, because the UI wants to highlight
terms and set warnings differently, and it would have to take a string apart again
for that.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctwatchtower.rules.schema import Rule, RuleSet


@dataclass
class Paragraph:
    """One section of the explanation."""

    kind: str  # "rule" | "inherited" | "info" | "warning"
    title: str = ""
    rows: list[str] = field(default_factory=list)


def quoted(items) -> list[str]:
    return [f"“{i}”" for i in items]


def _enumerate_terms(parts: list[str], conjunction: str = "or") -> str:
    if len(parts) == 1:
        return parts[0]
    return f"{', '.join(parts[:-1])} {conjunction} {parts[-1]}"


def _number(value: float) -> str:
    return f"{value:g}"


# How many terms before the list is cut short. Whoever has twenty lure words does not
# want to read all of them in the explanation. They want to see that the rule fires.
TERMS_SHOWN = 8


def _shortened(parts: list[str], conjunction: str = "or") -> str:
    if len(parts) <= TERMS_SHOWN:
        return _enumerate_terms(parts, conjunction)
    rest = len(parts) - TERMS_SHOWN
    return f"{', '.join(parts[:TERMS_SHOWN])} and {rest} more"


def _terms(condition) -> str:
    parts = [
        f"something matching the pattern {t.text}" if t.pattern else f"“{t.text}”"
        for t in condition.any_of
    ]
    return _shortened(parts)


def _spelling(rule: Rule) -> str:
    if rule.match is not None:
        return "With a match setting of its own."
    if not rule.tolerant:
        return "Words have to be spelled exactly like this."
    return (
        "Words are also caught with typos, digits for letters, confusable "
        "characters or separators pushed in between."
    )


def _rule_paragraph(rule: Rule) -> Paragraph:
    role = ", establishes the brand reference" if rule.counts_as_anchor else ""
    head = f"{_number(rule.weight)} points{role}."

    conditions = []
    for condition in rule.all_of:
        verb = "does not contain" if condition.negate else "contains"
        conditions.append(f"{verb} {_terms(condition)}")
    record = "The domain " + _enumerate_terms(conditions, "and") + "."

    rows = [head, record]
    if any(not t.pattern for c in rule.all_of for t in c.any_of):
        rows.append(_spelling(rule))
    if rule.exclude:
        rows.append(
            f"Except for: {_enumerate_terms(quoted(rule.exclude))}.")
    if rule.owned_domains:
        own = _enumerate_terms(quoted(rule.owned_domains))
        rows.append(f"Under {own} this rule never counts, that is our own infrastructure.")
    return Paragraph(kind="rule", title=rule.name, rows=rows)


def _classic_paragraphs(rs: RuleSet) -> list[Paragraph]:
    """Anchor and lure groups in the same language as the rules.

    The origin decides the kind: whatever sits in the tenant's own file is theirs and
    belongs visibly at the top; whatever comes in through `includes` gets folded away
    by the UI. Treating both the same would bury the tenant's own rules under the
    inherited ones.
    """
    own_file = f"{rs.tenant.id}.yaml"
    kind = lambda g: "rule" if g.source == own_file else "inherited"  # noqa: E731

    out = []
    for group in rs.anchors:
        out.append(
            Paragraph(
                kind=kind(group),
                title=group.description or "Brand anchor",
                rows=[
                    f"{_number(group.weight)} points, establishes the brand reference.",
                    "The domain contains "
                    + _shortened(quoted(group.terms)) + ".",
                ],
            )
        )
    for group in rs.lures:
        out.append(
            Paragraph(
                kind=kind(group),
                title=group.description or "Lure terms",
                rows=[
                    f"{_number(group.weight)} points, they only count on top of "
                    "something else, never on their own.",
                    ("The domain contains, as a word of its own, " if group.whole_word
                     else "The domain contains ")
                    + _shortened(quoted(group.terms))
                    + ".",
                ],
            )
        )
    return out


def explain_ruleset(rs: RuleSet, *, with_inherited: bool = False) -> list[Paragraph]:
    """The whole ruleset in sentences.

    `with_inherited` takes the classic anchor and lure groups along. Off by default:
    in the form they already sit next to it marked "inherited", and the explanation
    is meant to show what the user built themselves.
    """
    out: list[Paragraph] = []

    rules = list(rs.rules)
    if rules or with_inherited:
        out.append(
            Paragraph(
                kind="info",
                title="How points add up",
                rows=[
                    f"For “{rs.tenant.name}” every rule that applies counts. "
                    "Their points are added up; the sum is the score of the finding."
                ],
            )
        )
    out += [_rule_paragraph(rule) for rule in rules]
    if with_inherited:
        out += _classic_paragraphs(rs)

    if not rules and not with_inherited:
        out.append(
            Paragraph(kind="warning", title="No rule yet",
                      rows=["Without a rule nothing is found. Add one above."])
        )

    unreachable = rs.rules_without_prefilter
    if unreachable:
        out.append(
            Paragraph(
                kind="warning",
                title="Only fires by chance: "
                      + _enumerate_terms(quoted(unreachable)),
                rows=[
                    "This rule has no word in any required line, only patterns. The "
                    "prefilter works on words, though, and it does not let a domain "
                    "through to scoring at all if no word matches. So the rule only "
                    "fires for names that already stand out because of another rule. "
                    "The fix: take at least one word into one of the lines."
                ],
            )
        )

    # `example.com` and `.example.com` are two entries for one intention. Listing both
    # below each other doubles the list without saying anything.
    suffixes = {e.lstrip(".") for e in rs.allowlist.suppress.suffix}
    entries = [
        f"“{e}” and everything under it" if e in suffixes else f"“{e}”"
        for e in sorted(set(rs.allowlist.suppress.exact) | suffixes)
    ]
    if entries:
        out.append(
            Paragraph(kind="info", title="Never reported",
                      rows=[_enumerate_terms(entries, "and") + "."])
        )

    t, sc = rs.thresholds, rs.scoring
    thresholds = [
        f"From {_number(t.warning)} points it warns, from {_number(t.alert)} it alerts; "
        f"below {_number(t.persist)} nothing is stored at all."
    ]
    if sc.require_anchor:
        thresholds.append(
            "Without a rule that establishes the brand reference, a domain gets to "
            f"{_number(sc.anchor_missing_cap)} points at most."
        )

    bonuses = [f"{_number(c.bonus)} points" for c in rs.combos if c.bonus]
    if bonuses:
        thresholds.append(
            "When certain traits come together, points are added "
            f"({_enumerate_terms(bonuses)}), at most {_number(sc.max_combo_bonus)} in all."
        )
    out.append(Paragraph(kind="info", title="When it reports", rows=thresholds))
    return out


def as_text(paragraphs: list[Paragraph]) -> str:
    """The flat version. For tests, logs and anything that cannot do HTML."""
    return "\n\n".join("\n".join(filter(None, [a.title, *a.rows])) for a in paragraphs)
