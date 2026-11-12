"""The explanation object (§6.4) and the shapes the detectors work against.

No score without an explanation: every point of a finding has to be traceable here.

`CandidateName` and `CertContext` are `Protocol`s on purpose, so at runtime the
scoring depends on no other module. The concrete data classes come from
`normalize/names.py` and from the ingest (§2.3).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class CandidateName(Protocol):
    name: str
    unicode: str
    ascii: str
    is_idn: bool
    wildcard: bool
    labels: list[str]
    registrable: str
    subdomain: str
    tld: str
    skeleton: str
    prefilter_hits: list[str]


@runtime_checkable
class CertContext(Protocol):
    log_id: str
    idx: int
    seen_at: Any
    not_before: Any
    not_after: Any
    issuer_cn: str
    issuer_o: str
    serial: str
    sha256: str
    is_precert: bool
    names: list[str]


@dataclass(slots=True)
class Contribution:
    """One firing hit. `pts = w * s`, always, no exceptions."""

    rule: str
    w: float
    s: float
    type: str | None = None
    detail: str | None = None

    @property
    def pts(self) -> float:
        return round(self.w * self.s, 2)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"rule": self.rule, "w": self.w, "s": self.s, "pts": self.pts}
        if self.type:
            out["type"] = self.type
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass(slots=True)
class ScoreResult:
    score: int
    severity: str | None
    raw: float
    combo_bonus: float
    raw_effective: float
    phase: int = 1
    anchor_hit: bool = False
    suppressed: bool = False
    tenant: str = ""
    ruleset_hash: str = ""
    matched: list[str] = field(default_factory=list)
    contributions: list[Contribution] = field(default_factory=list)
    combos_applied: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """The JSON field for `findings.explanation` and the API."""
        d = asdict(self)
        d["contributions"] = [c.to_dict() for c in self.contributions]
        return d


def severity_for(score: float, thresholds: Any) -> str | None:
    """§6.5. `None` means: below `persist`, not stored at all.

    Materialised **once** when a finding is created (addendum §3) and never derived
    again from changed thresholds.
    """
    if score >= thresholds.alert:
        return "alert"
    if score >= thresholds.warning:
        return "warning"
    if score >= thresholds.persist:
        return "info"
    return None
