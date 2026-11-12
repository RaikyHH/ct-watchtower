""""All tenants" and "revoked watcher": two entries without a ruleset.

They stand in the tenant selector like real tenants. For that to work out, their
ids have to be reserved. Otherwise the same name would stand there twice and
nobody would know which one was meant.
"""

from __future__ import annotations

import pytest
from conftest import copy_rule_base

from ctwatchtower import pseudo_tenants
from ctwatchtower.app import create_app
from ctwatchtower.config import settings
from ctwatchtower.revocation import store
from ctwatchtower.rules.schema import Tenant


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "api_token", None)
    rules = copy_rule_base(tmp_path / "rules")
    application = create_app(db_path=tmp_path / "t.sqlite3", rules_dir=rules,
                             start_pipeline=False)
    yield application
    application.config["DB"].close()


# ─────────────────────────── The ids are reserved ────────────────────────


@pytest.mark.parametrize("ident", sorted(pseudo_tenants.PSEUDO))
def test_the_rule_schema_refuses_the_id(ident):
    """A hand-written YAML file must not take them either."""
    with pytest.raises(ValueError, match="is taken"):
        Tenant(id=ident, name="An attempt")


@pytest.mark.parametrize("ident", sorted(pseudo_tenants.PSEUDO))
def test_the_api_refuses_the_id_with_a_sentence(app, ident):
    response = app.test_client().post("/api/v1/tenants",
                                     json={"id": ident, "name": "An attempt"})
    assert response.status_code == 409
    # Not some validation error out of the depths, but an explanation.
    assert pseudo_tenants.PSEUDO[ident] in response.get_json()["error"]


def test_a_real_tenant_still_works(app):
    assert app.test_client().post(
        "/api/v1/tenants", json={"id": "real-name", "name": "Real"}).status_code == 201


# ─────────────────────────── All tenants ──────────────────────────────


def test_all_tenants_sums_over_everything():
    """`query_filter` is the place where a selection becomes a query filter."""
    assert pseudo_tenants.query_filter(pseudo_tenants.ALL_TENANTS) is None, "no filter means: everything"
    assert pseudo_tenants.query_filter(pseudo_tenants.REVOKED) == pseudo_tenants.REVOKED
    assert pseudo_tenants.query_filter("velton") == "velton"
    assert pseudo_tenants.query_filter(None) is None


def test_the_selector_shows_both_with_a_dividing_line(app):
    c = app.test_client()
    c.post("/api/v1/tenants", json={"id": "real-name", "name": "Real"})
    page = c.get("/live").get_data(as_text=True)
    for label in pseudo_tenants.PSEUDO.values():
        assert label in page
    # The dividing line carries the statement, not the colour.
    assert page.count("tenant-pseudo") == len(pseudo_tenants.PSEUDO)


def test_the_header_names_a_pseudo_tenant_too(app):
    c = app.test_client()
    c.post("/api/v1/tenants", json={"id": "real-name", "name": "Real"})
    page = c.get(f"/live?t={pseudo_tenants.ALL_TENANTS}").get_data(as_text=True)
    assert "All tenants" in page.split("</summary>")[0]


def test_the_rules_screen_does_not_ask_you_to_create_one(app):
    """Otherwise it says "No tenant yet" although there are some."""
    c = app.test_client()
    c.post("/api/v1/tenants", json={"id": "real-name", "name": "Real"})
    page = c.get(f"/rules?t={pseudo_tenants.ALL_TENANTS}").get_data(as_text=True)
    assert "Create a new tenant" not in page
    assert "has no rules" in page


# ─────────────────────────── The revoked watcher ──────────────────────────


def test_the_findings_list_shows_revoked_certificates(app):
    store.report_hit(app.config["DB"], {
        "leaf_sha256": "ab" * 32, "revoked_issuer": "Test-CA",
        "link_subject": "Intermediate-CA", "reason": "the key was compromised",
        "names": ["evil.example"], "names_total": 1, "chain": ["a", "b"]})
    page = app.test_client().get(f"/ui/findings-rows?t={pseudo_tenants.REVOKED}",
                                 headers={"Cookie": f"ctw_tenant={pseudo_tenants.REVOKED}"})
    text = page.get_data(as_text=True)
    assert "Intermediate-CA" in text
    assert "evil" in text, "the domain stands there - defanged, but readable"
    assert "data-revocation-hit" in text, "and it can be ticked off"


def test_the_watcher_works_with_no_tenants_at_all(app):
    """It hangs on no ruleset. Without tenants it must not redirect away."""
    response = app.test_client().get(f"/findings?t={pseudo_tenants.REVOKED}")
    assert response.status_code == 200, "no detour into the create dialog"


def test_the_counters_at_the_top_are_named_differently_there(app):
    """The same three tiles carry the triage state, not the severity."""
    page = app.test_client().get(f"/findings?t={pseudo_tenants.REVOKED}").get_data(as_text=True)
    header = page.split("</header>")[0]
    assert "Benign" in header and "Checked" in header
    assert "Alarm" not in header, "Alarm counted something else here than everywhere else"


def test_the_table_headers_match_the_content(app):
    """The hit count used to stand under "Score" and the chain link under "TLD"."""
    page = app.test_client().get(f"/findings?t={pseudo_tenants.REVOKED}").get_data(as_text=True)
    header = page.split("<tbody")[0]
    assert "Revoked link" in header
    assert "Score" not in header and "Registrar" not in header


def test_without_hits_the_screen_says_that_this_is_normal(app):
    text = app.test_client().get(
        f"/ui/findings-rows?t={pseudo_tenants.REVOKED}",
        headers={"Cookie": f"ctw_tenant={pseudo_tenants.REVOKED}"}).get_data(as_text=True)
    assert "normal case" in text
