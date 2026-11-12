"""Load, merge and validate the rulesets under `rules/`.

`includes` (§5.3) are resolved recursively: lists get merged, scalar values of the
including document win, cycles are a load error.

`_template.yaml` and everything under `examples/` are **not** active tenants: one
is the base for new tenants, the others are the templates from the spec.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from ruamel.yaml import YAML, YAMLError

from ctwatchtower.config import REPO_ROOT
from ctwatchtower.rules.schema import ListRule, RuleSet, raw_groups

log = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parents[3] / "rules"
SKIPPED_DIRS = {"common", "examples"}

def _list_rules(rs: RuleSet) -> list[tuple[str, ListRule]]:
    """All `post_enrichment` rules that point at a file under `data/`."""
    pe = rs.post_enrichment
    return [
        (name, rule)
        for name in ("privacy_registrar", "brand_protection_registrar")
        if isinstance(rule := getattr(pe, name), ListRule)
    ]


class RuleLoadError(Exception):
    """A rule file is broken. The caller keeps the old ruleset active."""


def _read(path: Path) -> dict[str, Any]:
    try:
        # Its own parser instance per call: ruamel keeps the read state in the
        # object. Two requests at once, and the rules screen validates on every
        # keystroke, used to step on each other's buffer, and a valid file came
        # back as "IndexError: string index out of range".
        data = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    except (OSError, YAMLError) as exc:
        raise RuleLoadError(f"{path.name}: YAML not readable: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise RuleLoadError(
            f"{path.name}: a YAML object was expected, found {type(data).__name__}")
    return data


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    """`over` wins for scalars, lists get appended (without duplicates).

    A list entry `over` brings along itself stays where it is but is replaced by the
    object from `over`: same content, but the origin is then the including file.
    Otherwise your own copy of a group would show up in the form as inherited and
    would drop out of the file on the next save.
    """
    for key, value in over.items():
        current = base.get(key)
        if isinstance(value, dict) and isinstance(current, dict):
            _merge(current, value)
        elif isinstance(value, list) and isinstance(current, list):
            own = [next((v for v in value if v == c), c) for c in current]
            base[key] = own + [v for v in value if v not in current]
        else:
            base[key] = value
    return base


# Origin per group dict: id -> (dict, file). The dict itself stays referenced, so no
# id gets handed out again while loading.
_Origins = dict[int, tuple[Any, str]]


def _resolve(path: Path, root: Path, origins: _Origins, chain: tuple[Path, ...] = ()) -> dict[str, Any]:
    path = path.resolve()
    if path in chain:
        cycle = " -> ".join(p.name for p in (*chain, path))
        raise RuleLoadError(f"cycle in includes: {cycle}")
    if not path.is_file():
        raise RuleLoadError(f"include not found: {path}")

    doc = _read(path)
    label = Path(os.path.relpath(path, root.resolve())).as_posix()
    for group in raw_groups(doc):
        origins[id(group)] = (group, label)
    includes = doc.pop("includes", []) or []
    merged: dict[str, Any] = {}
    for ref in includes:
        candidate = path.parent / ref
        if not candidate.is_file():
            candidate = root / ref
        _merge(merged, _resolve(candidate, root, origins, (*chain, path)))
    return _merge(merged, doc)


DEFAULT_ALERT = 64  # the template's alert threshold, if a file has none of its own


def _combos_to_points(merged: dict[str, Any], filename: str) -> None:
    """Convert `factor: 1.35` from the days of multipliers into fixed points.

    The reference point is the alert threshold: a finding that just triggers an
    alert gets as many extra points after the conversion as the factor gave it
    before. Below that the combination now counts for more, above it for less, and
    that difference is exactly what multipliers do, which is why they are gone: the
    same combination was worth 9 points once and 30 the next time.
    """
    combos = merged.get("combos")
    scoring = merged.get("scoring") if isinstance(merged.get("scoring"), dict) else {}
    thresholds = merged.get("thresholds") if isinstance(merged.get("thresholds"), dict) else {}
    # This conversion runs **before** validation, so nonsense arrives here too.
    # Anything that is not a number is left alone and is rejected by the schema
    # right afterwards, with a message that names the mistake.
    def _number(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    reference = _number(thresholds.get("alert")) or DEFAULT_ALERT

    converted = []
    for combo in combos if isinstance(combos, list) else []:
        if isinstance(combo, dict) and "factor" in combo and "bonus" not in combo:
            factor = _number(combo["factor"])
            if factor is None:
                continue
            del combo["factor"]
            combo["bonus"] = max(0, round((factor - 1) * reference))
            converted.append(f"{factor:g}x -> {combo['bonus']:g} points")
    if isinstance(scoring, dict) and (highest := _number(scoring.get("max_combo_factor"))) is not None:
        del scoring["max_combo_factor"]
        scoring["max_combo_bonus"] = max(0, round((highest - 1) * reference))
    if converted:
        log.warning(
            "%s: combo factors converted into points (%s). The reference point is "
            "the alert threshold %g, so the values deserve another look.",
            filename,
            ", ".join(converted),
            reference,
        )


def load_ruleset(path: str | Path, root: str | Path | None = None) -> RuleSet:
    """Load and validate one rule file including its includes."""
    path = Path(path)
    if root is None:
        # `examples/foo.yaml` includes `common/...` relative to the rules directory.
        root = path.parent.parent if path.parent.name in SKIPPED_DIRS else path.parent
    origins: _Origins = {}
    merged = _resolve(path, Path(root), origins)
    # `saturation_k` was a valid key until scoring went additive. A ruleset that is
    # in production must not fail over it: that would take the monitoring offline
    # over a number that does nothing any more anyway.
    scoring = merged.get("scoring")
    if isinstance(scoring, dict) and scoring.pop("saturation_k", None) is not None:
        log.warning(
            "%s: `scoring.saturation_k` is not evaluated any more, points are the "
            "score. The key can come out of the file.",
            path.name,
        )
    _combos_to_points(merged, path.name)
    try:
        rs = RuleSet.model_validate(merged)
    except ValidationError as exc:
        raise RuleLoadError(f"{path.name}: {exc}") from exc
    if rs.apiVersion == "ctwatchtower/v1":
        # In v1 the thresholds sat on the saturation scale, today they are points.
        # Quietly carrying on would mean alerting with the wrong thresholds, so
        # better to refuse loudly and have them converted.
        raise RuleLoadError(
            f"{path.name}: ruleset in the old form (apiVersion ctwatchtower/v1). "
            "Its thresholds sat on a saturation scale, today they are points. "
            "`python scripts/migrate_scoring.py` converts them without changing "
            "any severity."
        )
    for name, rule in _list_rules(rs):
        if not rule.list_file:
            continue
        if not (REPO_ROOT / rule.list_file).is_file():
            # At runtime this would only be a log line, and the rule would stay
            # silent forever. A rule that never fires should show up at load time.
            raise RuleLoadError(
                f"{path.name}: `post_enrichment.{name}` points at {rule.list_file}, "
                "and that file does not exist."
            )
    # Set the origin only after validation. A `source` in the file itself has
    # already been dropped by the schema. The lists line up 1:1 in order. For equal
    # groups the last merged document wins, as it does for scalars (`_merge`): the
    # including file before its includes, and of two includes the later one.
    for raw, group in zip(raw_groups(merged), [*rs.anchors, *rs.lures, *rs.tlds.groups], strict=True):
        group.source = origins[id(raw)][1]
    return rs


def ruleset_files(root: str | Path = RULES_DIR) -> list[Path]:
    """Active tenant files only: no `_template.yaml`, no `common/`, no `examples/`."""
    root = Path(root)
    if not root.is_dir():
        return []
    return sorted(
        p
        for p in root.glob("*.y*ml")
        if not p.name.startswith("_") and p.parent.name not in SKIPPED_DIRS
    )


def load_rulesets(root: str | Path = RULES_DIR) -> list[RuleSet]:
    """All active tenants. One broken file does not stop the others."""
    out: list[RuleSet] = []
    for path in ruleset_files(root):
        try:
            rs = load_ruleset(path, root)
        except RuleLoadError as exc:
            log.warning("ruleset skipped: %s", exc)
            continue
        if rs.tenant.enabled:
            out.append(rs)
    return out


def all_prefilter_terms(rulesets: list[RuleSet]) -> set[str]:
    """Stage 1 of the prefilter (§4.2): anchors, their permutations, all lure terms.

    Across all tenants. The ingest builds exactly one Aho-Corasick automaton from it.
    """
    terms: set[str] = set()
    for rs in rulesets:
        for group in rs.anchors:
            terms.update(group.terms)
        for permutations in rs.permutation_index.values():
            terms.update(permutations)
        for group in rs.lures:
            terms.update(group.terms)
        # Rules: every word, those from AND lines too. Letting too much through
        # costs throughput, letting too little through costs findings, and the
        # prefilter must never be the reason a rule does not fire.
        for rule in rs.rules:
            terms.update(rule.prefilter_words)
    return {t for t in terms if len(t) >= 3}


class RuleStore:
    """Hot reload (§5.1) with the failure case **per file**: if one file fails, the
    last valid version of that file stays active. Deleted files disappear, disabled
    tenants (`enabled: false`) go inactive but stay visible.

    - `rulesets`: active tenants. What the pipeline scores
    - `all_rulesets`: everything loaded, disabled included. For display and for
      switching a tenant back on
    """

    def __init__(self, root: str | Path = RULES_DIR) -> None:
        self.root = Path(root)
        self._by_file: dict[Path, RuleSet] = {}
        self._stamp: tuple[tuple[str, float], ...] = ()
        self.reload()

    def _fingerprint(self) -> tuple[tuple[str, float], ...]:
        return tuple((str(p), p.stat().st_mtime) for p in sorted(self.root.rglob("*.y*ml")))

    def reload(self) -> list[RuleSet]:
        loaded: dict[Path, RuleSet] = {}
        for path in ruleset_files(self.root):
            try:
                loaded[path] = load_ruleset(path, self.root)
            except RuleLoadError as exc:
                kept = self._by_file.get(path)
                log.warning("ruleset %s: %s",
                            "old version stays active" if kept else "skipped", exc)
                if kept is not None:
                    loaded[path] = kept
        self._by_file = loaded
        self._stamp = self._fingerprint()
        return self._active()

    def _active(self) -> list[RuleSet]:
        return [rs for rs in self._by_file.values() if rs.tenant.enabled]

    def _fresh(self) -> None:
        if self._fingerprint() != self._stamp:
            self.reload()

    @property
    def rulesets(self) -> list[RuleSet]:
        """Active tenants; reloads as soon as a file has changed."""
        self._fresh()
        return self._active()

    @property
    def all_rulesets(self) -> list[RuleSet]:
        """Every loaded tenant, disabled ones included (`tenant.enabled` says which)."""
        self._fresh()
        return list(self._by_file.values())

    def get(self, tenant_id: str) -> RuleSet | None:
        """Disabled tenants too. The pipeline asks `rulesets`, not `get`. Whoever
        cannot open a disabled tenant any more cannot switch it back on either."""
        return next((rs for rs in self.all_rulesets if rs.tenant.id == tenant_id), None)

    def prefilter_terms(self) -> set[str]:
        return all_prefilter_terms(self.rulesets)
