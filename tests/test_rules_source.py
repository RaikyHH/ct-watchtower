"""`source` on anchor, lure and TLD groups: set by the loader, dropped on input,
with no influence on `ruleset_hash` or the score."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from conftest import copy_rule_base
from ruamel.yaml import YAML
from test_rules_loader import write
from test_scoring_support import make_candidate

from ctwatchtower.rules.loader import load_ruleset
from ctwatchtower.rules.schema import RuleSet, drop_source
from ctwatchtower.scoring.engine import score_candidate

REPO_RULES = Path(__file__).resolve().parents[1] / "rules"


@pytest.fixture
def tenant_file(tmp_path: Path) -> Path:
    write(tmp_path / "common" / "lures.yaml", "lures:\n  - {terms: [login], weight: 14}\n")
    write(
        tmp_path / "common" / "tlds.yaml",
        "includes: [common/lures.yaml]\n"
        "tlds:\n  groups:\n    - {name: billig, weight: 25, list: [top]}\n",
    )
    return write(
        tmp_path / "check.yaml",
        "includes: [common/tlds.yaml]\n"
        "tenant: {id: check, name: Check}\n"
        "anchors:\n  - {terms: [velton], weight: 45}\n"
        "lures:\n  - {terms: [account], weight: 9}\n  - {terms: [login], weight: 14}\n"
        "tlds:\n  groups:\n    - {name: eigen, weight: 30, list: [cfd]}\n",
    )


def sources(rs: RuleSet) -> dict[str, list[str | None]]:
    return {
        "anchors": [g.source for g in rs.anchors],
        "lures": [g.source for g in rs.lures],
        "tlds": [g.source for g in rs.tlds.groups],
    }


def test_loader_sets_the_file_each_group_comes_from(tenant_file: Path) -> None:
    rs = load_ruleset(tenant_file)
    assert sources(rs) == {
        "anchors": ["check.yaml"],
        # a nested include; the `login` group stands byte for byte in the own file
        # too. Then the own origin wins (at the place of the include), otherwise it
        # would fall out of the file on the next save from the form
        "lures": ["check.yaml", "check.yaml"],
        "tlds": ["common/tlds.yaml", "check.yaml"],
    }
    assert [g.terms for g in rs.lures] == [["login"], ["account"]]


def test_source_is_in_model_dump_for_the_api(tenant_file: Path) -> None:
    dump = load_ruleset(tenant_file).model_dump(by_alias=True, exclude_none=True)
    assert dump["anchors"][0]["source"] == "check.yaml"
    assert dump["tlds"]["groups"][0]["source"] == "common/tlds.yaml"


def test_repo_template_marks_common_groups_as_inherited() -> None:
    rs = load_ruleset(REPO_RULES / "_template.yaml")
    assert rs.lures and all(g.source.startswith("common/") for g in rs.lures + rs.tlds.groups)


def test_submitted_source_is_dropped_not_rejected(tenant_file: Path) -> None:
    loaded = load_ruleset(tenant_file)
    # The form plays the API answer back including `source`, a forged one included.
    form = loaded.model_dump(by_alias=True, exclude_none=True)
    form["anchors"][0]["source"] = "common/untergeschoben.yaml"
    echoed = RuleSet.model_validate(form)
    assert set(sources(echoed)["anchors"] + sources(echoed)["lures"] + sources(echoed)["tlds"]) == {None}
    assert "source" not in echoed.model_dump(exclude_none=True)["anchors"][0]


def test_source_written_into_a_file_is_ignored_and_replaced(tmp_path: Path) -> None:
    path = write(
        tmp_path / "check.yaml",
        "tenant: {id: check, name: Check}\n"
        "anchors:\n  - {terms: [velton], weight: 45, source: common/gelogen.yaml}\n",
    )
    assert load_ruleset(path).anchors[0].source == "check.yaml"


def test_ruleset_hash_and_score_do_not_depend_on_source(tenant_file: Path) -> None:
    loaded = load_ruleset(tenant_file)
    echoed = RuleSet.model_validate(loaded.model_dump(by_alias=True))
    assert echoed.anchors[0].source is None
    assert loaded.ruleset_hash == echoed.ruleset_hash
    for domain in ("velton-login.top", "account-velton.cfd", "example.de"):
        a = score_candidate(loaded, make_candidate(domain))
        b = score_candidate(echoed, make_candidate(domain))
        assert (a.score, a.contributions, a.combos_applied) == (b.score, b.contributions, b.combos_applied)


def test_drop_source_keeps_it_out_of_the_yaml_round_trip() -> None:
    yaml = YAML()
    doc = yaml.load(
        "# the comment stays\n"
        "tenant: {id: check, name: Check}\n"
        "anchors:\n  - {terms: [velton], weight: 45, source: check.yaml}\n"
        "lures:\n  - {terms: [account], weight: 9, source: check.yaml}\n"
        "tlds:\n  groups:\n    - {name: eigen, weight: 30, list: [cfd], source: check.yaml}\n"
    )
    buf = io.StringIO()
    yaml.dump(drop_source(doc), buf)
    assert "source" not in buf.getvalue()
    assert "# the comment stays" in buf.getvalue()
    # Form junk before the validation: do not crash, the validation reports it.
    junk = {"tlds": "broken", "anchors": None, "lures": ["broken"]}
    assert drop_source(dict(junk)) == junk


# The API writes the raw document, not `model_dump()`; without `drop_source` in
# `api/routes.py::_dump` a `source` sent back landed in the file.
def test_api_form_echo_never_writes_source_into_the_file(tmp_path: Path) -> None:
    from ctwatchtower.app import create_app

    rules = tmp_path / "rules"
    copy_rule_base(rules)
    app = create_app(db_path=tmp_path / "t.sqlite3", rules_dir=rules, start_pipeline=False)
    try:
        client = app.test_client()
        assert client.post("/api/v1/tenants", json={"id": "check", "name": "Check"}).status_code == 201
        body = {"anchors": [{"terms": ["velton"], "weight": 45, "source": "check.yaml"}]}
        resp = client.patch("/api/v1/tenants/check/rules", json=body)
        assert resp.status_code == 200
        assert "source" not in (rules / "check.yaml").read_text(encoding="utf-8")
    finally:
        app.config["DB"].close()


def test_identical_group_from_two_includes_is_inherited_from_the_later_one(tmp_path: Path) -> None:
    # As with scalars the document merged later wins; the group is inherited either
    # way. Only the own file must not lose it.
    for name in ("eins", "zwei"):
        write(tmp_path / "common" / f"{name}.yaml", "lures:\n  - {terms: [login], weight: 14}\n")
    main = write(
        tmp_path / "t.yaml",
        "includes: [common/eins.yaml, common/zwei.yaml]\ntenant: {id: t, name: T}\n",
    )
    assert [g.source for g in load_ruleset(main).lures] == ["common/zwei.yaml"]


def test_validate_shows_the_real_origin_not_the_temporary_one(tmp_path: Path) -> None:
    """The validation writes a temporary copy and loads that. Without a correction
    all the own groups would carry its name. The file name would go outside, and
    "own" could no longer be told apart from "inherited"."""
    from ctwatchtower.app import create_app

    rules = copy_rule_base(tmp_path / "rules")
    app = create_app(db_path=tmp_path / "t.sqlite3", rules_dir=rules, start_pipeline=False)
    try:
        client = app.test_client()
        client.post("/api/v1/tenants", json={"id": "check", "name": "Check"})
        response = client.post(
            "/api/v1/tenants/check/rules/validate",
            json={"anchors": [{"terms": ["velton"], "weight": 45}]},
        )
        data = response.get_json()
        assert data["valid"] is True
        quellen = {g["source"] for g in data["rules"]["anchors"]}
        assert quellen == {"check.yaml"}
        assert not any(q.endswith(".tmp") for q in quellen)
    finally:
        app.config["DB"].close()
