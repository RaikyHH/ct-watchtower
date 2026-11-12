from __future__ import annotations

from pathlib import Path

import pytest
from conftest import copy_rule_base

from ctwatchtower.rules.loader import (
    DEFAULT_ALERT,
    RuleLoadError,
    RuleStore,
    all_prefilter_terms,
    load_ruleset,
    load_rulesets,
    ruleset_files,
)

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
EXAMPLES = sorted((RULES_DIR / "examples").glob("*.yaml"))


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.stem)
def test_every_example_ruleset_validates(path: Path) -> None:
    rs = load_ruleset(path)
    assert rs.tenant.id == path.stem


def test_template_validates_and_has_no_anchors() -> None:
    rs = load_ruleset(RULES_DIR / "_template.yaml")
    assert rs.anchors == []
    assert rs.lures and rs.tlds.groups, "the includes were not resolved"
    assert rs.allowlist.downweight, "allowlist_cloud.yaml fehlt"


def test_template_and_examples_are_not_active_tenants(tmp_path: Path) -> None:
    # Against a copy of the shipped parts, not against the real `rules/`: anyone
    # who uses the platform has productive tenants lying there (§14.5).
    rules = copy_rule_base(tmp_path / "rules")
    names = [p.name for p in ruleset_files(rules)]
    assert "_template.yaml" not in names
    assert not any("examples" in str(p) for p in ruleset_files(rules))
    assert load_rulesets(rules) == []


def test_includes_merge_lists_and_let_the_including_document_win(tmp_path: Path) -> None:
    write(
        tmp_path / "common" / "base.yaml",
        "lures:\n  - {terms: [login], weight: 14}\nscoring: {top_n: 40}\n",
    )
    main = write(
        tmp_path / "kunde.yaml",
        "includes: [common/base.yaml]\n"
        "tenant: {id: kunde, name: Kunde}\n"
        "lures:\n  - {terms: [account], weight: 9}\n"
        "scoring: {top_n: 8}\n",
    )
    rs = load_ruleset(main)
    assert [g.terms for g in rs.lures] == [["login"], ["account"]]
    assert rs.scoring.top_n == 8


def test_nested_includes_are_resolved(tmp_path: Path) -> None:
    write(tmp_path / "a.yaml", "tlds: {default_weight: 3}\n")
    write(tmp_path / "b.yaml", "includes: [a.yaml]\nlures:\n  - {terms: [login], weight: 1}\n")
    main = write(tmp_path / "t.yaml", "includes: [b.yaml]\ntenant: {id: t, name: T}\n")
    rs = load_ruleset(main)
    assert rs.tlds.default_weight == 3 and rs.lures[0].terms == ["login"]


def test_include_cycle_is_a_load_error(tmp_path: Path) -> None:
    write(tmp_path / "a.yaml", "includes: [b.yaml]\ntenant: {id: a, name: A}\n")
    write(tmp_path / "b.yaml", "includes: [a.yaml]\n")
    with pytest.raises(RuleLoadError, match="cycle"):
        load_ruleset(tmp_path / "a.yaml")


def test_self_include_is_a_load_error(tmp_path: Path) -> None:
    write(tmp_path / "a.yaml", "includes: [a.yaml]\ntenant: {id: a, name: A}\n")
    with pytest.raises(RuleLoadError, match="cycle"):
        load_ruleset(tmp_path / "a.yaml")


def test_missing_include_is_a_load_error(tmp_path: Path) -> None:
    write(tmp_path / "a.yaml", "includes: [weg.yaml]\ntenant: {id: a, name: A}\n")
    with pytest.raises(RuleLoadError, match="not found"):
        load_ruleset(tmp_path / "a.yaml")


def test_broken_yaml_is_a_load_error(tmp_path: Path) -> None:
    write(tmp_path / "a.yaml", "tenant: {id: a\n  name: [[[\n")
    with pytest.raises(RuleLoadError):
        load_ruleset(tmp_path / "a.yaml")


def test_non_object_document_is_a_load_error(tmp_path: Path) -> None:
    write(tmp_path / "a.yaml", "- eins\n- zwei\n")
    with pytest.raises(RuleLoadError, match="a YAML object"):
        load_ruleset(tmp_path / "a.yaml")


def test_invalid_ruleset_is_a_load_error(tmp_path: Path) -> None:
    write(tmp_path / "a.yaml", "tenant: {id: A_B, name: x}\n")
    with pytest.raises(RuleLoadError):
        load_ruleset(tmp_path / "a.yaml")


def test_load_rulesets_skips_broken_and_disabled_tenants(tmp_path: Path, caplog) -> None:
    write(tmp_path / "good.yaml", "tenant: {id: good, name: Good}\n")
    write(tmp_path / "off.yaml", "tenant: {id: off, name: Off, enabled: false}\n")
    write(tmp_path / "broken.yaml", "tenant: {id: 'NOT OK', name: x}\n")
    write(tmp_path / "_template.yaml", "tenant: {id: template, name: T}\n")
    assert [rs.tenant.id for rs in load_rulesets(tmp_path)] == ["good"]


def test_all_prefilter_terms_spans_every_tenant(tmp_path: Path) -> None:
    rulesets = [load_ruleset(p) for p in EXAMPLES]
    terms = all_prefilter_terms(rulesets)
    assert {"paylio", "vantabank", "stellax", "zelo", "velton"} <= terms  # the anchors
    assert {"login", "wallet", "refund"} <= terms  # the lures
    assert "paylo" in terms and "pay1io" in terms  # the permutations
    assert all(len(t) >= 3 for t in terms)
    assert all_prefilter_terms([]) == set()


def test_rulestore_keeps_the_last_valid_set_when_a_file_breaks(tmp_path: Path) -> None:
    good = write(tmp_path / "kunde.yaml", "tenant: {id: kunde, name: Kunde}\n")
    store = RuleStore(tmp_path)
    assert [rs.tenant.id for rs in store.rulesets] == ["kunde"]
    assert store.get("kunde") is not None and store.get("gibtsnicht") is None
    assert store.prefilter_terms() == set()

    good.write_text("tenant: {id: 'KAPUTT!', name: x}\n", encoding="utf-8")
    assert [rs.tenant.id for rs in store.reload()] == ["kunde"]


def test_rulestore_picks_up_changes(tmp_path: Path) -> None:
    write(tmp_path / "kunde.yaml", "tenant: {id: kunde, name: Kunde}\n")
    store = RuleStore(tmp_path)
    write(tmp_path / "zwei.yaml", "tenant: {id: zwei, name: Zwei}\n")
    assert sorted(rs.tenant.id for rs in store.rulesets) == ["kunde", "zwei"]


def test_empty_include_file_is_allowed(tmp_path: Path) -> None:
    write(tmp_path / "empty.yaml", "# just a comment\n")
    main = write(tmp_path / "a.yaml", "includes: [empty.yaml]\ntenant: {id: a, name: A}\n")
    assert load_ruleset(main).tenant.id == "a"


def test_missing_rules_directory_yields_nothing(tmp_path: Path) -> None:
    assert ruleset_files(tmp_path / "doesnotexist") == []
    assert load_rulesets(tmp_path / "gibtsnicht") == []


def ids(rulesets) -> list[str]:
    return sorted(rs.tenant.id for rs in rulesets)


def test_rulestore_deleting_the_last_tenant_takes_effect(tmp_path: Path) -> None:
    last = write(tmp_path / "kunde.yaml", "tenant: {id: kunde, name: Kunde}\n")
    store = RuleStore(tmp_path)
    last.unlink()
    assert store.reload() == [] and store.all_rulesets == []


def test_rulestore_disabling_the_last_tenant_takes_effect_but_keeps_it_visible(tmp_path: Path) -> None:
    last = write(tmp_path / "kunde.yaml", "tenant: {id: kunde, name: Kunde}\n")
    store = RuleStore(tmp_path)
    last.write_text("tenant: {id: kunde, name: Kunde, enabled: false}\n", encoding="utf-8")
    # No longer scored, but still findable. Otherwise it could not be reactivated.
    assert store.reload() == []
    stillgelegt = store.get("kunde")
    assert stillgelegt is not None and not stillgelegt.tenant.enabled
    assert [(rs.tenant.id, rs.tenant.enabled) for rs in store.all_rulesets] == [("kunde", False)]
    # Reaktivieren
    last.write_text("tenant: {id: kunde, name: Kunde}\n", encoding="utf-8")
    assert ids(store.reload()) == ["kunde"]


def test_rulestore_keeps_the_last_valid_state_per_file(tmp_path: Path) -> None:
    a = write(tmp_path / "a.yaml", "tenant: {id: a, name: A}\n")
    b = write(tmp_path / "b.yaml", "tenant: {id: b, name: B}\n")
    store = RuleStore(tmp_path)
    # a breaks, b is shut down, c arrives broken: a stays in its old state, b goes
    # inactive, and c does not exist.
    a.write_text("tenant: {id: 'KAPUTT!', name: x}\n", encoding="utf-8")
    b.write_text("tenant: {id: b, name: B, enabled: false}\n", encoding="utf-8")
    write(tmp_path / "c.yaml", "tenant: [broken\n")
    assert ids(store.reload()) == ["a"]
    assert ids(store.all_rulesets) == ["a", "b"]
    # A broken file that is then deleted disappears as well.
    a.unlink()
    assert store.reload() == []


def test_missing_registrar_list_is_a_load_error(tmp_path: Path) -> None:
    # At runtime such a rule would stay mute without anybody noticing.
    write(
        tmp_path / "a.yaml",
        "tenant: {id: a, name: A}\n"
        "post_enrichment:\n"
        "  privacy_registrar: {weight: 10, list_file: data/gibtsnicht.yaml}\n",
    )
    with pytest.raises(RuleLoadError, match="gibtsnicht.yaml"):
        load_ruleset(tmp_path / "a.yaml")


def test_legacy_saturation_key_is_dropped_instead_of_failing(tmp_path: Path, caplog) -> None:
    """A tenant that is in operation must not fail on a key from the time of the
    saturation curve. That would take the monitoring off the air."""
    write(
        tmp_path / "a.yaml",
        "tenant: {id: a, name: A}\nscoring: {saturation_k: 38, top_n: 7}\n",
    )
    rs = load_ruleset(tmp_path / "a.yaml")
    assert rs.scoring.top_n == 7
    assert not hasattr(rs.scoring, "saturation_k")
    assert "saturation_k" in caplog.text


def test_old_combo_factors_are_converted_into_points(tmp_path: Path, caplog) -> None:
    """A tenant in operation must not come to a halt on a multiplier.
    The reference point is the alert threshold: whatever just sets off an alert gets
    exactly as many points added after the conversion as the factor gave before."""
    write(
        tmp_path / "a.yaml",
        "tenant: {id: a, name: A}\n"
        "thresholds: {alert: 60}\n"
        "scoring: {max_combo_factor: 2.0}\n"
        "combos:\n"
        "  - {when: [anchor, lure], factor: 1.35}\n"
        "  - {when: [anchor], bonus: 7}\n",
    )
    rs = load_ruleset(tmp_path / "a.yaml")
    assert [c.bonus for c in rs.combos] == [21, 7]  # (1.35 − 1) × 60 = 21
    assert rs.scoring.max_combo_bonus == 60
    assert "combo factors converted into points" in caplog.text


def test_without_an_own_alert_threshold_the_template_one_holds(tmp_path: Path) -> None:
    write(
        tmp_path / "a.yaml",
        "tenant: {id: a, name: A}\ncombos: [{when: [anchor], factor: 1.5}]\n",
    )
    rs = load_ruleset(tmp_path / "a.yaml")
    assert rs.combos[0].bonus == round(0.5 * DEFAULT_ALERT)


def test_a_combo_factor_that_is_not_a_number_is_left_alone(tmp_path: Path) -> None:
    """The conversion reads what is there, it does not trust it. A `factor` that is
    not a number stays untouched, and the schema then says so instead of the loader
    turning it into a wrong number of points."""
    write(
        tmp_path / "a.yaml",
        "tenant: {id: a, name: A}\ncombos: [{when: [anchor], factor: later}]\n",
    )
    with pytest.raises(RuleLoadError):
        load_ruleset(tmp_path / "a.yaml")


def test_a_list_rule_without_a_file_is_not_a_load_error(tmp_path: Path) -> None:
    """Only a `list_file` that points nowhere is an error. A rule that carries a
    weight alone is legitimate: it matches over the names built into the code."""
    write(
        tmp_path / "a.yaml",
        "tenant: {id: a, name: A}\n"
        "post_enrichment: {brand_protection_registrar: {weight: -40}}\n",
    )
    rs = load_ruleset(tmp_path / "a.yaml")
    assert rs.post_enrichment.brand_protection_registrar.weight == -40
    assert not rs.post_enrichment.brand_protection_registrar.list_file
