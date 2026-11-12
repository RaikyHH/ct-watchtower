"""Detectors with context: certificate (§5.2 `certificate`), enrichment
(§5.2 `post_enrichment`) and exceptions (§5.2 `allowlist`).

All three may be called without their context; the UI test field scores a bare
domain with no certificate and no RDAP/DNS data.
"""

from __future__ import annotations

import functools
import logging
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from ctwatchtower.config import REPO_ROOT
from ctwatchtower.rules.detectors.text import AnchorHit
from ctwatchtower.rules.schema import ListRule, MatchPatterns, RuleSet
from ctwatchtower.scoring.explain import CandidateName, CertContext, Contribution

_FREE_EV_HINTS = ("ev ", "extended validation")

log = logging.getLogger(__name__)
_missing_lists: set[str] = set()  # log each missing list only once


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _matches(patterns: MatchPatterns, name: str, registrable: str) -> str | None:
    if name in patterns.exact or registrable in patterns.exact:
        return f"exact:{name}"
    for suffix in patterns.suffix:
        if name.endswith(suffix) or name == suffix.lstrip("."):
            return f"suffix:{suffix}"
    for pattern in patterns.regex:
        if re.search(pattern, name):
            return f"regex:{pattern}"
    return None


def suppressed_by(rs: RuleSet, cand: CandidateName) -> str | None:
    """Hard suppress (§5.2): a hit means no finding is created at all."""
    return _matches(rs.allowlist.suppress, cand.name.lower(), (cand.registrable or "").lower())


def detect_allowlist(rs: RuleSet, cand: CandidateName) -> list[Contribution]:
    """Soft suppress: points off, nothing else."""
    out: list[Contribution] = []
    name, registrable = cand.name.lower(), (cand.registrable or "").lower()
    for i, entry in enumerate(rs.allowlist.downweight):
        hit = _matches(entry.match, name, registrable)
        if hit:
            label = entry.note or hit
            out.append(Contribution(f"allow:downweight:{i}", w=entry.weight, s=1.0, detail=label))
    return out


def detect_certificate(
    rs: RuleSet, cand: CandidateName, cert: CertContext | None, anchors: list[AnchorHit]
) -> list[Contribution]:
    cfg = rs.certificate
    if cert is None:
        return []
    out: list[Contribution] = []
    names = list(getattr(cert, "names", None) or [])

    if cfg.san_count and len(names) >= cfg.san_count.threshold:
        out.append(
            Contribution("cert:san_count", w=cfg.san_count.weight, s=1.0, detail=f"{len(names)} SANs")
        )

    if cfg.san_brand_fanout and anchors:
        terms = {h.term for h in anchors}
        matching = sum(1 for n in names if any(t in n.lower() for t in terms))
        if matching >= cfg.san_brand_fanout.min_matching_sans:
            out.append(
                Contribution(
                    "cert:san_brand_fanout",
                    w=cfg.san_brand_fanout.weight,
                    s=1.0,
                    detail=f"{matching} brand-like SANs",
                )
            )

    if cfg.validity_days and cfg.validity_days.enabled:
        start, end = _as_datetime(cert.not_before), _as_datetime(cert.not_after)
        if start and end:
            days = (end - start).days
            v = cfg.validity_days
            hit = (v.max_days is not None and days <= v.max_days) or (
                v.min_days is not None and days >= v.min_days
            )
            if hit:
                out.append(
                    Contribution("cert:validity_days", w=v.weight, s=1.0, detail=f"{days} days"))

    issuer = f"{cert.issuer_o or ''} {cert.issuer_cn or ''}".lower()
    for group in cfg.issuer_groups:
        # Deliberately simple: real EV needs the policy OID, which does not arrive
        # on the bus (§2.3). The hint in the issuer name is enough here. Upgrade:
        # carry the OID through the ingest.
        is_ev = group.match_ev and any(h in issuer for h in _FREE_EV_HINTS)
        if is_ev or any(m.lower() in issuer for m in group.match):
            out.append(
                Contribution(f"cert:issuer:{group.name}", w=group.weight, s=1.0, detail=issuer.strip())
            )
            break

    return out


@functools.lru_cache(maxsize=16)
def _registrar_list(path: str, mtime: float) -> tuple[tuple[str, ...], frozenset[int]]:
    """Registrar list (`registrars:` name parts, `iana_ids:` numbers). `mtime` is in
    the key, so a changed file is read again on the next call."""
    doc = YAML(typ="safe").load(Path(path).read_text(encoding="utf-8")) or {}
    names = tuple(str(n).strip().lower() for n in doc.get("registrars") or [] if str(n).strip())
    return names, frozenset(int(i) for i in doc.get("iana_ids") or [])


def _registrar_listed(rule: ListRule, enrichment: Mapping[str, Any]) -> str | None:
    """The registrar from the enrichment if it is in `rule.list_file`, else `None`.

    Names match as a case-insensitive substring (`markmonitor` matches "MarkMonitor
    Inc."), IANA ids match exactly.
    """
    name = str(enrichment.get("registrar") or "")
    iana = enrichment.get("registrar_iana_id")
    if not rule.list_file or not (name or iana):
        return None
    path = REPO_ROOT / rule.list_file
    try:
        names, ids = _registrar_list(str(path), path.stat().st_mtime)
    except OSError:
        if rule.list_file not in _missing_lists:
            _missing_lists.add(rule.list_file)
            log.warning("registrar list %s not readable, the rule does not fire",
                        rule.list_file)
        return None
    low = name.lower()
    if (iana is not None and int(iana) in ids) or any(n in low for n in names):
        return name or f"IANA {iana}"
    return None


def detect_post_enrichment(rs: RuleSet, enrichment: Mapping[str, Any] | None) -> list[Contribution]:
    """Phase 2 (§7.9). `enrichment` is a flat dict of RDAP/DoH results."""
    if not enrichment:
        return []
    pe = rs.post_enrichment
    out: list[Contribution] = []

    age = enrichment.get("domain_age_days")
    if age is not None and pe.domain_age:
        younger = [r for r in pe.domain_age if r.max_age_days is not None and age <= r.max_age_days]
        older = [r for r in pe.domain_age if r.min_age_days is not None and age >= r.min_age_days]
        rule = min(younger, key=lambda r: r.max_age_days) if younger else (
            max(older, key=lambda r: r.min_age_days) if older else None
        )
        if rule is not None:
            out.append(Contribution("post:domain_age", w=rule.weight, s=1.0, detail=f"{age} days"))

    # Two registrar lists. `privacy_registrar` also fires off a ready-made flag in
    # the enrichment (the older form, without a list).
    for key, rule in (
        ("privacy_registrar", pe.privacy_registrar),
        ("brand_protection_registrar", pe.brand_protection_registrar),
    ):
        if rule is None:
            continue
        listed = _registrar_listed(rule, enrichment)
        if listed or enrichment.get(key):
            detail = listed or str(enrichment.get("registrar") or "")
            out.append(Contribution(f"post:{key}", w=rule.weight, s=1.0, detail=detail))

    if pe.nameserver_patterns:
        servers = [str(n).lower() for n in enrichment.get("nameservers") or []]
        for pattern in pe.nameserver_patterns.regex:
            hit = next((n for n in servers if re.search(pattern, n)), None)
            if hit:
                weight = pe.nameserver_patterns.weight
                out.append(Contribution("post:nameserver_patterns", w=weight, s=1.0, detail=hit))
                break

    if pe.no_resolution and enrichment.get("no_resolution"):
        out.append(Contribution("post:no_resolution", w=pe.no_resolution.weight, s=1.0))

    if pe.parking_detected and enrichment.get("parking_detected"):
        out.append(Contribution("post:parking_detected", w=pe.parking_detected.weight, s=1.0))

    return out
