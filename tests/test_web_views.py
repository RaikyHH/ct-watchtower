"""The interface: every screen answers, and the presentation rules from §12.2
hold. Defanging, homoglyph marking, IDN in both forms and above all:
no domain name lands as an `href` onto itself."""

from __future__ import annotations

import json
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from conftest import copy_rule_base
from ruamel.yaml import YAML

from ctwatchtower.app import create_app
from ctwatchtower.db import upsert_finding
from ctwatchtower.normalize.names import CertContext, normalize
from ctwatchtower.web.views import render_domain

REPO_RULES = Path(__file__).resolve().parents[1] / "rules"
SCREENS = ["/live", "/findings", "/rules", "/campaigns", "/system"]

ANCHORS = {
    "anchors": [{"terms": ["velton"], "weight": 45, "match": {"exact": True, "homoglyph": True}}]
}


def cert(*names: str) -> CertContext:
    now = datetime.now(UTC)
    return CertContext(
        log_id="oak2026h1",
        idx=42,
        seen_at=now,
        not_before=now,
        not_after=now,
        issuer_cn="R11",
        issuer_o="Let's Encrypt",
        serial="01",
        sha256="".join(names)[:16].ljust(64, "0"),
        is_precert=False,
        names=list(names),
    )


@pytest.fixture
def app(tmp_path):
    """Against a *copy* of the rules directory. The real `rules/` stays untouched."""
    rules = tmp_path / "rules"
    copy_rule_base(rules)
    app = create_app(db_path=tmp_path / "t.sqlite3", rules_dir=rules, start_pipeline=False)
    yield app
    app.config["DB"].close()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def tenant(client):
    assert client.post("/api/v1/tenants", json={"id": "velton", "name": "Velton"}).status_code == 201
    assert client.patch("/api/v1/tenants/velton/rules", json=ANCHORS).status_code == 200
    return "velton"


@pytest.fixture
def finding(app, client, tenant):
    pipeline = app.config["PIPELINE"]
    pipeline.rulesets(force=True)
    events = pipeline.process(cert("velton-login.top", "www.velton-login.top"))
    assert events
    return events[0]


# ─────────────────────────── Reachability ────────────────────────────


@pytest.mark.parametrize("path", SCREENS)
def test_screen_answers(client, tenant, path):
    res = client.get(path)
    assert res.status_code == 200
    assert b"CT&#8209;WATCHTOWER" in res.data


@pytest.mark.parametrize("path", SCREENS)
def test_screen_without_a_tenant(client, path):
    """The empty state: everything leads into the rules screen with the create dialog."""
    res = client.get(path, follow_redirects=True)
    assert res.status_code == 200
    assert "Create a new tenant" in res.get_data(as_text=True)


def test_index_redirects_to_live(client):
    assert client.get("/").headers["Location"].endswith("/live")


def test_fragments(client, finding):
    for path in ("live-rows", "findings-rows", "campaigns"):
        assert client.get(f"/ui/{path}?t=velton").status_code == 200
    assert client.get("/ui/system").status_code == 200
    assert client.get(f"/ui/finding/{finding['id']}").status_code == 200
    assert client.get("/ui/finding/doesnotexist").status_code == 404


# ───────────────── The safety of the presentation (§12.2) ─────────────


def test_defanging_on_by_default(client, finding):
    body = client.get("/ui/live-rows?t=velton").get_data(as_text=True)
    assert "[.]" in body
    assert "velton-login" in body


def test_defanging_can_be_switched_off(client, finding):
    client.set_cookie("ctw_defang", "0")
    body = client.get("/ui/live-rows?t=velton").get_data(as_text=True)
    assert "[.]" not in body


def test_no_href_onto_the_domain_itself(client, finding):
    """No `href` or `src` anywhere in the detail panel points at the finding."""
    body = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    for attr, url in re.findall(r'(href|src)="([^"]*)"', body):
        assert not re.match(r"https?://(www\.)?velton-login\.top", url), (attr, url)
        assert "//velton-login.top" not in url
    for _, url in re.findall(r'(href)="([^"]*)"', body):
        if "velton-login.top" in url:  # deeplinks may carry it only as a parameter
            assert "velton-login.top" not in urlsplit(url).netloc, url
            assert 'rel="noopener noreferrer"' in body


def test_homoglyph_and_idn(app):
    """Non-ASCII marked with its code point, and confusable digits as well."""
    with app.test_request_context("/"):
        html = str(render_domain("pаypal.com"))  # a Cyrillic а
        assert 'class="dom-hl"' in html
        assert "U+0430" in html
        assert "[.]" in html
        assert str(render_domain("payli0.com")).count('class="dom-hl"') == 1


def test_escaping(app):
    with app.test_request_context("/"):
        html = str(render_domain('<script>x</script>.com'))
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


def test_idn_shows_both_forms(client, app, tenant):
    """Punycode *and* Unicode. The rendered form can deceive (§12.2.3)."""
    cand = normalize("veltón.com")
    with app.app_context():
        fid, _ = upsert_finding(
            app.config["DB"], tenant, cand, cert(cand.name),
            score=70, severity="warning", explanation={"matched": ["anchor:velton(homoglyph)"]},
        )
    body = client.get(f"/ui/finding/{fid}").get_data(as_text=True)
    assert "xn--" in body
    assert "dom-uni" in body
    assert "U+00F3" in body  # ó marked, with the code point in the tooltip


# ───────────────────────── Rules and the test field ─────────────────────


def test_rule_form_shows_its_own_anchors(client, tenant):
    body = client.get("/rules?t=velton").get_data(as_text=True)
    assert "velton" in body
    assert "Test field" in body
    assert "inherited through includes" in body  # inherited lure terms are read-only


OWN_LOGIN = {
    **ANCHORS,
    "lures": [{"description": "own", "terms": ["login", "overdraft"], "weight": 30}],
}


def form_state(client, tenant_id: str) -> dict:
    """The JSON block `app.js` works from. Exactly what the form knows."""
    body = client.get(f"/rules?t={tenant_id}").get_data(as_text=True)
    return json.loads(re.search(r'id="rule-state">(.*?)</script>', body, re.S).group(1))


def test_own_and_inherited_by_source(app, client, tenant):
    """`login` comes over `common/lures_en.yaml` *and* out of `velton.yaml`; the own
    group is editable, the inherited one read-only, whatever the order."""
    from ctwatchtower.web.views import rule_form

    assert client.patch("/api/v1/tenants/velton/rules", json=OWN_LOGIN).status_code == 200
    rs = app.config["RULES"].get("velton")
    assert {g.source for g in rs.lures} == {"common/lures_en.yaml", "velton.yaml"}

    with app.test_request_context():
        for order in (list(rs.lures), list(reversed(rs.lures))):
            form = rule_form(rs.model_copy(update={"lures": order}))
            assert form["own"]["lures"] == OWN_LOGIN["lures"]
            assert "login" in form["inherited_lures"]
            assert "overdraft" not in form["inherited_lures"]
            assert form["inherited_anchors"] == []

    assert "source" not in json.dumps(form_state(client, "velton"))  # a read field stays out


def financial(app, client) -> Path:
    """`rules/examples/banking.yaml` as the active tenant, in the copy."""
    rules = Path(app.config["RULES_DIR"])
    path = rules / "banking.yaml"
    shutil.copy(rules / "examples" / "banking.yaml", path)
    assert client.get("/api/v1/tenants/banking/rules").status_code == 200
    return path


def own_groups(path: Path) -> dict:
    doc = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    return {"anchors": doc["anchors"], "lures": doc["lures"], "tlds": doc["tlds"]}


def test_saving_without_a_change_loses_nothing(app, client):
    """A round trip: load the form state and send all of it back (the worst case.
    `app.js` does not send unchanged values at all). The weights per group,
    `exclude`, `owned_domains` and all the match settings stay as they were."""
    path = financial(app, client)
    before = own_groups(path)
    own = form_state(client, "banking")["own"]
    assert own["anchors"][0]["exclude"] == ["stellar"]
    assert [g["weight"] for g in own["lures"]] == [14, 7]  # two groups, two weights

    body = {"anchors": own["anchors"], "lures": own["lures"], "tlds": {"groups": own["tlds"]}}
    assert client.patch("/api/v1/tenants/banking/rules", json=body).status_code == 200
    assert own_groups(path) == before


def test_changing_a_term_changes_only_that_one(app, client):
    path = financial(app, client)
    before = own_groups(path)
    own = form_state(client, "banking")["own"]
    own["lures"][1]["terms"].remove("advisor")  # like a click on the × in the chip
    own["lures"][1]["terms"].append("relationship")  # and an "add"

    res = client.patch("/api/v1/tenants/banking/rules", json={"lures": own["lures"]})
    assert res.status_code == 200
    after = own_groups(path)
    before["lures"][1]["terms"] = [t for t in before["lures"][1]["terms"]
                                if t != "advisor"] + ["relationship"]
    assert after == before


def test_form_knows_suppression_own_rules_and_structure(app, client):
    """What is actually needed while tuning a ruleset has to arrive in the form.
    Otherwise the only way left is writing the YAML by hand."""
    from ctwatchtower.web.views import rule_form

    financial(app, client)
    body = {
        "allowlist": {"suppress": {"exact": ["fremde-firma.de"], "suffix": [".fremde-firma.de"]}},
        "custom": [{"id": "kombi", "regex": "amt[-_.]?lakeside", "weight": 30, "counts_as_anchor": True}],
        "rules": [{"name": "Place and procedure", "weight": 30, "counts_as_anchor": True,
                   "all_of": [{"any_of": ["lakeside"]}, {"any_of": ["customerdesk"]}]}],
        "structure": {"hyphen_count": {"threshold": 3}, "shannon_entropy": {"threshold": 4.2}},
    }
    assert client.patch("/api/v1/tenants/banking/rules", json=body).status_code == 200

    own = form_state(client, "banking")["own"]
    assert own["allowlist"]["suppress"]["exact"] == ["fremde-firma.de"]
    assert own["custom"][0]["counts_as_anchor"] is True
    # Multi-part rules (`all_of`) have to come along. An authority can only be
    # covered that way - "a place name AND an administrative term" - and the form
    # has long shown them. Were the key missing, the tab would report "0 rules"
    # above a file full of rules.
    assert own["rules"][0]["name"] == "Place and procedure"
    # `exclude` and the typo tolerance sit in the group itself.
    assert own["anchors"][0]["exclude"] == ["stellar"]
    assert "fuzzy" in own["anchors"][0]["match"]

    with app.test_request_context():
        form = rule_form(app.config["RULES"].get("banking"))
    # The thresholds arrive effective, not raw: the form shows what actually holds.
    assert form["structure"].hyphen_count.threshold == 3
    assert form["structure"].shannon_entropy.threshold == pytest.approx(4.2)
    # What is inherited appears separately and read-only. Own entries not twice.
    assert "fremde-firma.de" not in form["inherited_suppress"]
    assert ".fremde-firma.de" not in form["inherited_suppress"]


def test_changing_one_structure_threshold_leaves_the_rest_alone(app, client):
    """The form sends only the threshold that was moved. The others must not be
    written into the own file because of it."""
    path = financial(app, client)
    before = YAML(typ="safe").load(path.read_text(encoding="utf-8")).get("structure") or {}
    assert client.patch(
        "/api/v1/tenants/banking/rules",
        json={"structure": {"hyphen_count": {"threshold": 3}}},
    ).status_code == 200
    after = YAML(typ="safe").load(path.read_text(encoding="utf-8"))["structure"]
    assert after["hyphen_count"]["threshold"] == 3
    for detector, value in before.items():
        if detector != "hyphen_count":
            assert after[detector] == value


def test_test_field_replaces_only_the_own_groups(app, client, tenant):
    assert client.patch("/api/v1/tenants/velton/rules", json=OWN_LOGIN).status_code == 200
    res = client.post(
        "/ui/lookup",
        json={"domain": "velton-login.top", "tenant": "velton", "patch": {"lures": []}},
    )
    assert "lure:login" in res.get_data(as_text=True)  # the inherited `login` stays in effect


def test_tenant_delete_contract(client, finding):
    """The dialog in `app.js` builds on exactly this contract: a 409 with a count, then force."""
    res = client.delete("/api/v1/tenants/velton")
    assert res.status_code == 409
    assert res.get_json()["findings"] >= 1
    assert client.get("/rules?t=velton").status_code == 200  # nothing deleted
    assert client.delete("/api/v1/tenants/velton?confirm=velton").status_code == 204


def test_test_field_scores_the_unsaved_state(client, tenant):
    res = client.post(
        "/ui/lookup",
        json={
            "domain": "velton-security-login.top",
            "tenant": "velton",
            "patch": {"anchors": [{"terms": ["velton"], "weight": 60}]},
        },
    )
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert "anchor:velton" in body
    assert "[.]" in body  # the defanging holds here too


def test_test_field_reports_an_unusable_name(client, tenant):
    res = client.post("/ui/lookup", json={"domain": "not a name", "tenant": "velton"})
    assert res.status_code == 200
    assert "not a scorable name" in res.get_data(as_text=True)


def test_test_field_without_a_tenant(client):
    assert client.post("/ui/lookup", json={"domain": "a.de", "tenant": "x"}).status_code == 404


def test_system_fragment_with_a_filled_queue_history(client, app) -> None:
    """The sampler stores measuring points as a dict, the graph computes with numbers.

    With an empty history the fallback holds and the error stays hidden, so the
    screen broke only in operation, as soon as the first measuring point was there.
    """
    from datetime import UTC, datetime

    history = app.config["PIPELINE"].queue_history
    for pct in (0.0, 12.5, 61.0, 94.0):
        history.append({"depth_pct": pct, "t": datetime.now(UTC).isoformat()})

    r = client.get("/ui/system")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # Thirty columns, however many measuring points there are; missing ones are unlit.
    assert body.count('class="column"') == 30
    # 94 % lies in the pause zone: the topmost segment has to be red.
    assert '<i class="alert">' in body


# ────────── The enrichment: only on a click, never while paging ──────────

APP_JS = (
    Path(__file__).resolve().parents[1] / "src/ctwatchtower/web/static/app.js"
).read_text(encoding="utf-8")


def js_blocks(opener: str) -> list[str]:
    """Cut out every body from `opener` to the matching closing brace."""
    out, start = [], 0
    while (start := APP_JS.find(opener, start)) != -1:
        depth = 0
        for i in range(APP_JS.index("{", start), len(APP_JS)):
            depth += (APP_JS[i] == "{") - (APP_JS[i] == "}")
            if depth == 0:
                out.append(APP_JS[start : i + 1])
                break
        start += len(opener)
    assert out, opener
    return out


def test_paging_sets_off_no_enrichment():
    """j/k only pages. Fifty key presses must not be fifty queries (§16).

    What gets checked is the place where it would go wrong: everything in the keyboard
    handler **before** the Enter branch must not reach `openDetail`. Enter itself is a
    deliberate single action like a click, and it may.
    """
    for block in js_blocks("addEventListener('keydown'"):
        before_enter = block.split("ev.key === 'Enter'")[0]
        assert "openDetail" not in before_enter
        assert "/enrich" not in block, "the call belongs in `openDetail` alone"


def test_enter_and_a_click_are_the_only_ways_to_the_enrichment():
    """The call appears exactly once in the code, and only two deliberate actions
    lead there: a click on the row, or Enter on the selected one."""
    assert APP_JS.count("/enrich`") == 1
    assert "/enrich`" in js_blocks("async function openDetail")[0]
    for block in js_blocks("rows.addEventListener('click'"):
        assert "openDetail" in block
    keyboard = js_blocks("addEventListener('keydown'")[0]
    enter_branch = keyboard.split("ev.key === 'Enter'")[1]
    assert "openDetail" in enter_branch


def test_the_keyboard_reaches_the_details():
    """With j/k you select a row, with Enter you open it.

    Without the Enter branch the keyboard would reach every row but no finding -
    opening one would only work with the mouse.
    """
    keyboard = js_blocks("addEventListener('keydown'")[0]
    for key in ("'j'", "'k'", "'c'", "'f'", "'Enter'"):
        assert key in keyboard, key


def test_panel_handles_every_contract_state():
    """200/202 carry five states; each one gets a sentence of its own in the panel."""
    handler = js_blocks("function enrichNote")[0]
    for status in ("queued", "pending", "disabled", "quota", "busy"):
        assert f"'{status}'" in handler
    assert "res.quota" in handler
    # The switched-off state has to be named. The name of the environment variable
    # used to stand here; since the settings page exists it is switched on in the
    # interface, so the test checks the statement instead of where it comes from.
    assert "switched off" in handler


def test_detail_shows_what_the_enrichment_delivers(app, client, finding):
    """The enrichment stands beside it, it corrects nothing.

    The score at the top stays the finding's; what the registration data would give
    is a statement of its own. A score that changes while you look at it confuses
    more than the more exact number helps.
    """
    app.config["DB"].execute(
        "UPDATE findings SET enrich_state = ?, score_enriched = ?, enrich_note = ?,"
        " status_note = ?, domain_changed = ?, registrar = ? WHERE id = ?",
        ("done", 15, "score 15: brand_protection_registrar (-60)",
         "reported by the tenant as a domain of their own",
         "2026-09-01T00:00:00+00:00", "Example Registrar", finding["id"]),
    )
    body = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    assert 'data-enrich-state="done"' in body
    assert "with registration data: <b" in body and ">15<" in body
    assert "brand_protection_registrar" in body
    assert str(finding["score"]) in body, "the actual score still stands at the top"
    assert "reported by the tenant as a domain of their own" in body
    assert "Last changed" in body and "2026-09-01" in body


def test_detail_reports_the_enrichment_state(app, client, finding):
    """Fresh out of the pipeline it says `skipped`. Never enriched automatically (§16).

    On `pending` the polling in app.js keeps waiting; any other value ends it.
    """
    body = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    assert 'data-enrich-state="skipped"' in body
    assert 'id="enrich-note"' in body

    app.config["DB"].execute(
        "UPDATE findings SET enrich_state='pending' WHERE id=?", (finding["id"],)
    )
    body = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    assert 'data-enrich-state="pending"' in body


def test_deeplinks_come_out_of_the_configuration(client, finding):
    """No longer four hard-wired ones, but `config/deeplinks.yaml` (§7.8)."""
    body = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    assert "urlscan.io" in body and "Wayback Machine" in body
    # Without an A record there is no AbuseIPDB link. `deeplinks()` drops empty placeholders.
    assert "abuseipdb.com" not in body


def test_the_endpoint_keeps_the_contract_the_ui_assumes(client, finding):
    """The UI posts to exactly this route and reads `status` and `enrich_state`.

    No network traffic: `ENRICH_ENABLED` is off by default, and the answer is then
    `disabled`. Should it be on, the test checks the shape of the contract only.
    """
    r = client.post(f"/api/v1/findings/{finding['id']}/enrich")
    assert r.status_code in (200, 202)
    body = r.get_json()
    assert body["status"] in ("pending", "done", "disabled", "quota", "busy", "queued")
    assert "enrich_state" in body
    if body["status"] == "quota":
        assert "counts" in body["quota"] and "limits" in body["quota"]

    # The contract: an unknown finding → a 404 with `status: "unknown"`. As long as the
    # enrichment is off, the endpoint answers "disabled" without looking for the finding
    # at all. The UI copes with both (it only shows the note), but the contract is not
    # yet met here.
    r = client.post("/api/v1/findings/doesnotexist/enrich")
    assert r.get_json()["status"] in ("unknown", "disabled")
    if r.get_json()["status"] == "unknown":
        assert r.status_code == 404


def test_security_headers_on_every_answer(client) -> None:
    """The second line behind `render_domain`: domain names are attacker input."""
    r = client.get("/rules")
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp.split("style-src")[0]
    assert "frame-ancestors 'none'" in csp and "default-src 'none'" in csp
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"


def test_no_inline_scripts_and_no_foreign_origins(client) -> None:
    """Otherwise the CSP would need `unsafe-inline` and Google would see every user's IP."""
    html = client.get("/rules").get_data(as_text=True)
    executable = [t for t in re.findall(r"<script([^>]*)>", html) if "application/json" not in t]
    assert all("src=" in t for t in executable), f"an inline script was found: {executable}"
    assert "fonts.googleapis.com" not in html and "fonts.gstatic.com" not in html
    assert client.get("/static/fonts.css").status_code == 200


def test_every_slider_has_its_readout_and_its_key(app, client):
    """The template and `app.js` are coupled through the id: `#in-X` belongs to `#val-X`,
    and X is the key under which the change goes into the PATCH.

    Without this test it drifted apart: the threshold sliders were called `persist`
    in one place and `thresholds.persist` in the other, on which threshold changes
    were silently dropped. Nothing of it was visible. The slider moved, the number
    was right, and nothing was saved.
    """
    financial(app, client)
    body = client.get("/rules?t=banking").get_data(as_text=True)
    sliders = set(re.findall(r'class="rule-slider[^"]*"[^>]*id="in-([^"]+)"', body))
    readouts = set(re.findall(r'class="slider-val" id="val-([^"]+)"', body))
    assert sliders, "no sliders found - was the template rebuilt?"
    assert sliders <= readouts, f"without a readout: {sorted(sliders - readouts)}"
    # `patch()` in app.js expects these keys verbatim. `saturation_k` is no longer
    # among them: points are the score, there is nothing left to compress.
    assert {"persist", "warning", "alert", "anchor_missing_cap"} <= sliders
    assert "saturation_k" not in sliders


def test_tabs_and_panels_match_up(app, client):
    """Every tab points at a panel that exists, otherwise the click goes nowhere
    and the page simply stays as it is."""
    financial(app, client)
    body = client.get("/rules?t=banking").get_data(as_text=True)
    tabs = re.findall(r'id="tab-([a-z]+)" data-tab="([a-z]+)"', body)
    panels = set(re.findall(r'id="panel-([a-z]+)"[^>]*role="tabpanel"', body))
    assert len(tabs) == 4
    assert {ident for ident, _ in tabs} == panels
    assert all(ident == data for ident, data in tabs)
    # Exactly one is open to begin with. Count only inside the tab bar: the tenant
    # switch uses `aria-selected` for the chosen tenant.
    bar = re.search(r'<nav class="tabs".*?</nav>', body, re.S).group(0)
    assert bar.count('aria-selected="true"') == 1


def test_deleting_a_tenant_leaves_a_trace(client, finding, app):
    """The access log lives in the container and is gone at the next rebuild. That is
    exactly when it is needed: when a tenant and its findings had vanished, there was
    no way left to tell where the request came from. So the trace belongs in the database."""
    assert client.delete("/api/v1/tenants/velton?confirm=velton").status_code == 204
    rows = app.config["DB"].execute(
        "SELECT action, target, detail, source FROM audit ORDER BY at DESC"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["action"] == "tenant.delete"
    assert rows[0]["target"] == "velton"
    assert "findings deleted too" in rows[0]["detail"]
    assert rows[0]["source"]


def test_a_refused_delete_leaves_no_trace(client, finding, app):
    """The 409 is not an intervention. It should not fill the log with failed attempts."""
    assert client.delete("/api/v1/tenants/velton").status_code == 409
    assert app.config["DB"].execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 0


def test_replacing_a_commented_list_yields_readable_yaml(app, client):
    """Replacing a list that carries a comment used to make the file unreadable.

    ruamel passes the old value's comment on to the following place and writes
    `combos: -` out of it. Not valid YAML. Saving therefore failed for every
    commented ruleset, with an error message about a temporary file that nobody
    can place.
    """
    rules = Path(app.config["RULES_DIR"])
    (rules / "commented.yaml").write_text(
        "apiVersion: ctwatchtower/v2\nkind: RuleSet\n"
        "tenant: {id: commented, name: K}\n"
        "lures:\n"
        "  # A comment above the lures\n"
        "  - {terms: [login], weight: 14}\n"
        "combos:\n"
        "  - {when: [anchor, lure], bonus: 15}\n",
        encoding="utf-8",
    )
    res = client.patch("/api/v1/tenants/commented/rules", json={"lures": []})
    assert res.status_code == 200, res.get_json()
    # The file has to be loadable again afterwards, otherwise the tenant is dead.
    assert client.get("/api/v1/tenants/commented/rules").status_code == 200
    text = (rules / "commented.yaml").read_text(encoding="utf-8")
    assert "combos: -" not in text
    assert YAML(typ="safe").load(text)["combos"][0]["bonus"] == 15


def test_spectrum_colours_the_zones_by_meaning() -> None:
    """The colour says what happens: from 50 % the ingest throttles, from 80 % it pauses.
    A line chart would make you read the scale for that."""
    from ctwatchtower.web.views import queue_chart

    empty, middle, full = queue_chart([0.0, 60.0, 95.0])[-3:]
    assert set(empty) == {"off"}
    assert "warn" in middle and "alert" not in middle
    assert "alert" in full
    # From the top down: first the unlit ones, then the hot zones.
    assert full.index("alert") < full.index("on")


def test_minute_spectrum_counts_empty_minutes_too(app, client, finding) -> None:
    """A minute without a finding is a zero, not a gap, otherwise quiet periods would
    close up and the spectrum would show a course that never happened."""
    from ctwatchtower.web.views import findings_per_bucket, minute_chart

    with app.test_request_context("/?t=velton"):
        values = findings_per_bucket("velton")
        days_mode = findings_per_bucket("velton", resolution="day")
    assert len(days_mode) == 30 and days_mode[-1] >= 1  # today's finding sits on the right
    assert len(values) == 30
    assert sum(values) >= 1  # the fixture lies in the current minute

    # A single finding has to light at least one segment. Unlit segments carry no
    # class; the design colours them as the base state.
    columns = minute_chart([0, 1, 10], segments=10)
    assert set(columns[0]) == {""}
    assert columns[1].count("on") == 1
    assert columns[2].count("on") == 10
    # Rounded up, never down to zero: at a peak of 30 one finding still lights up.
    assert minute_chart([1, 30], segments=10)[0].count("on") == 1
    # And the column fills from the bottom. It sits on `column-reverse`.
    assert minute_chart([1, 10], segments=4)[0][0] == "on"


def test_answers_do_not_give_away_the_server_name(client):
    """The name of the server in use tells an attacker what to look for holes in,
    and helps nobody else."""
    for path in ("/live", "/api/v1/status"):
        header = client.get(path).headers.get("Server", "")
        assert "gunicorn" not in header.lower() and "werkzeug" not in header.lower(), (path, header)


def test_simple_requests_can_change_nothing(client, tenant):
    """Without a login this is the defence against CSRF.

    What a foreign page could send from the browser without a preflight - a form,
    text, a file upload - is not read as a payload. Everything else needs a
    preflight, which fails without CORS permission.
    """
    for kind in ("application/x-www-form-urlencoded", "text/plain", "multipart/form-data"):
        res = client.post("/api/v1/tenants", data="id=evil&name=B", content_type=kind)
        assert res.status_code == 400, kind
    assert client.get("/api/v1/tenants/evil/rules").status_code == 404


def test_no_cors_permission_for_foreign_origins(client, tenant):
    """Without `Access-Control-Allow-Origin` the browser aborts every foreign request
    before it reaches the server."""
    res = client.options(
        "/api/v1/tenants",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "DELETE"},
    )
    assert "Access-Control-Allow-Origin" not in res.headers


def test_a_field_without_a_value_does_not_get_the_empty_state_padding(client, finding):
    """`.empty` is the empty state of a whole screen and carries 48px of padding.

    A field in the detail panel has no value far more often than not, and it used to
    carry the same class name. Every one of the eight registration fields then became
    a flex box with 48px of padding, which blew the panel apart - and it only showed
    with the enrichment switched off, where every field is empty at once.

    The dead-rule test above cannot see this: both classes were called `empty`, so it
    was satisfied. This one pins the two apart by name.
    """
    body = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    fields = re.findall(r'class="value([^"]*)"', body)
    assert fields, "no value fields in the panel - was the template rebuilt?"
    assert not any("empty" in f for f in fields), (
        "a field carries the screen's empty-state class", fields)

    css = (Path(__file__).resolve().parents[1] / "src/ctwatchtower/web/static/app.css").read_text(
        encoding="utf-8"
    )
    screen = re.search(r"(?<![\w.-])\.empty\s*\{[^}]*\}", css)
    assert screen and "padding:48px" in screen.group(0).replace(" ", ""), (
        "the screen empty state lost its padding, so this test no longer proves anything"
    )


def test_no_dead_rules_in_the_stylesheet():
    """Every class in the stylesheet has to be produced somewhere.

    After a rebuild, rules otherwise stay behind for elements that no longer exist -
    they look like design that applies, and they are not.
    """


    root = Path(__file__).resolve().parents[1] / "src/ctwatchtower/web"
    css = (root / "static/app.css").read_text(encoding="utf-8")
    # The embedded SVGs of the background carry `www.w3.org`; without taking them
    # out, the test would take that for a class `.w3`. And a comment that mentions
    # a class is not a rule.
    css = re.sub(r'url\("data:[^"]*"\)', "", css)
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    sources = "".join(
        p.read_text(encoding="utf-8")
        for p in [*(root / "templates").glob("*.html"), root / "static/app.js", root / "views.py"]
    )
    # Names that come about only at runtime: `sev-{{ f.severity }}` in the templates,
    # `paragraph ${a.kind}` in the script. The test reads the prefixes out of the
    # sources itself, so it needs no care for every new dynamic name.
    prefixes = {m.group(1) for m in re.finditer(r"([a-z][\w]*)-(?:\{\{|\$\{)", sources)}
    # The values put in behind `${a.kind}`: the kinds of explanation paragraph.
    dynamic = {"rule", "inherited", "warning", "info"}
    classes = {m.group(1) for m in re.finditer(r"\.([a-zA-Z][\w-]*)", css)}
    unused = sorted(
        k for k in classes - dynamic
        if k not in sources and k.rsplit("-", 1)[0] not in prefixes
    )
    assert prefixes, "no dynamic prefixes found - is the detection broken?"
    assert not unused, f"rules without an element: {unused}"


def test_counters_are_filters_at_the_same_time(client, tenant):
    """The three counters in the instrument bar filter by severity. Without `data-sev`
    the click goes nowhere and the counter would be mere decoration."""
    body = client.get("/live").get_data(as_text=True)
    for sev in ("alert", "warning", "info"):
        assert f'class="counter" data-sev="{sev}" aria-pressed="false"' in body


def test_counters_are_not_an_alert_surface(client, tenant):
    """A red-filled box with a zero in it draws the eye to nothing.

    The severity sits in the chip beside it (`sev-chip`); the counter itself stays
    neutral, so that a zero does not look like a finding.
    """
    css = (Path(__file__).resolve().parents[1] / "src/ctwatchtower/web/static/app.css").read_text(
        encoding="utf-8"
    )
    rule = re.search(r"\.counter\s*\{[^}]*\}", css)
    assert rule, "the counters no longer have a rule of their own"
    assert "--color-alert" not in rule.group(0), rule.group(0)


def test_panel_title_carries_no_box_colours(client, finding):
    """The name in the detail panel gets the text colour of its severity, not the
    box class.

    That one colours the background. On an alert, red text stood on a red ground
    and could no longer be read.
    """
    body = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    title = re.search(r'class="panel-title dom (title-[a-z]+)"', body).group(1)
    assert title.startswith("title-")
    css = (Path(__file__).resolve().parents[1] / "src/ctwatchtower/web/static/app.css").read_text(
        encoding="utf-8"
    )
    for rule in re.findall(r"\.title-\w+\s*\{[^}]*\}", css):
        assert "background" not in rule, rule


def test_top_bar_wraps_instead_of_overflowing():
    """In a narrow window the bar has to wrap. With a fixed height its content ran
    over the edge and pushed itself over the wordmark."""
    css = (Path(__file__).resolve().parents[1] / "src/ctwatchtower/web/static/app.css").read_text(
        encoding="utf-8"
    )
    rule = re.search(r"\.topbar\s*\{[^}]*\}", css).group(0)
    assert "flex-wrap:wrap" in rule.replace(" ", ""), rule
    assert not re.search(r"(?<!min-)\bheight:", rule), rule


def test_exoneration_appears_as_a_note_instead_of_swallowing_the_finding(app, client, finding):
    """An exonerated finding used to vanish by itself, which came of the enrichment
    overwriting the score. Now a sentence with a button stands in the panel."""
    conn = app.config["DB"]
    conn.execute(
        "UPDATE findings SET score=90, score_enriched=12,"
        " enrich_note=? WHERE id=?",
        ("score 12: brand_protection_registrar (-40)", finding["id"]),
    )
    conn.commit()
    text = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    assert "The registration data speaks against this finding" in text
    assert "brand_protection_registrar (-40)" in text
    assert "below the threshold" in text
    assert 'data-set-status="false_positive"' in text


def test_no_note_on_a_small_deviation_or_a_decided_finding(app, client, finding):
    conn = app.config["DB"]
    conn.execute(
        "UPDATE findings SET score=90, score_enriched=85, enrich_note='score 85' WHERE id=?",
        (finding["id"],),
    )
    conn.commit()
    panel = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    assert "speaks against this finding" not in panel

    # Anyone who has already judged the finding no longer needs the note.
    conn.execute(
        "UPDATE findings SET score_enriched=5, status='confirmed' WHERE id=?", (finding["id"],)
    )
    conn.commit()
    panel = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    assert "speaks against this finding" not in panel


def test_an_explaining_comment_above_a_section_stays_put(app, client):
    """The block above a key explains what the section is for, and it holds for the
    new content too. Only what hung on the replaced value itself falls away."""
    rules = Path(app.config["RULES_DIR"])
    (rules / "commented2.yaml").write_text(
        "apiVersion: ctwatchtower/v2\nkind: RuleSet\n"
        "tenant: {id: commented2, name: K}\n"
        "\n"
        "# These terms come out of the 2026-03 evaluation; before changing them\n"
        "# please check them against the situation report.\n"
        "lures:\n"
        "  - {terms: [login], weight: 14}\n",
        encoding="utf-8",
    )
    res = client.patch(
        "/api/v1/tenants/commented2/rules",
        json={"lures": [{"terms": ["account"], "weight": 20}]},
    )
    assert res.status_code == 200, res.get_json()
    text = (rules / "commented2.yaml").read_text(encoding="utf-8")
    assert "out of the 2026-03 evaluation" in text
    assert "against the situation report" in text
    assert YAML(typ="safe").load(text)["lures"][0]["terms"] == ["account"]


def test_system_shows_feeds_and_daily_caps(client, tenant):
    """Both existed, neither was written anywhere. An interface nobody can find,
    nobody uses, and a daily cap you cannot see is one you cannot keep to."""
    text = client.get("/ui/system").get_data(as_text=True)
    assert "/feed/velton/indicators.csv" in text
    assert "/feed/velton/domains.txt" in text
    assert "Daily caps" in text
    # Depending on the switch, either the counters or the reason there are none.
    assert ("UTC day" in text) or ("Switched off" in text)


def test_reported_can_be_set_in_the_panel(app, client, finding):
    """Sending happens in the mail client, and the application never hears of it.
    Without this button, `reported` would stay a status nobody can set, although the
    retention is precisely what protects it from being deleted."""
    text = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    assert 'data-set-status="reported"' in text

    assert client.patch(
        f"/api/v1/findings/{finding['id']}", json={"status": "reported"}
    ).status_code == 200
    # Afterwards the button is gone. Reporting twice makes no sense.
    again = client.get(f"/ui/finding/{finding['id']}").get_data(as_text=True)
    assert 'data-set-status="reported"' not in again


def test_system_shows_per_channel_whether_it_is_stuck(app, client, monkeypatch):
    """"Ready" on the whole helps nobody when the webhook works and the mail is stuck.

    Nothing is sent while doing this: the setup is only set, not used.
    """
    from ctwatchtower.config import settings as s

    monkeypatch.setattr(s, "notify_enabled", True)
    monkeypatch.setattr(s, "notify_webhook_url", "https://intern.invalid/hook")
    monkeypatch.setattr(s, "mail_enabled", True)
    monkeypatch.setattr(s, "mail_from", "watchtower@example.invalid")
    monkeypatch.setattr(s, "mail_to", "security@example.invalid")
    monkeypatch.setattr(s, "mail_smtp_host", "mail.example.invalid")

    text = client.get("/ui/system").get_data(as_text=True)
    assert "webhook" in text and "mail" in text
    assert "mail.example.invalid:587" in text
    # The button for the test message is clickable only once everything is filled in.
    assert 'id="test-mail"' in text
    assert "disabled" not in text.split('id="test-mail"')[1][:120]


def test_system_says_why_the_mail_does_not_work(app, client, monkeypatch):
    from ctwatchtower.config import settings as s

    monkeypatch.setattr(s, "notify_enabled", True)
    monkeypatch.setattr(s, "mail_enabled", True)
    monkeypatch.setattr(s, "mail_from", "watchtower@example.invalid")
    monkeypatch.setattr(s, "mail_to", "")          # the recipient is missing

    text = client.get("/ui/system").get_data(as_text=True)
    assert "sender or recipient missing" in text
    # And the button stays disabled instead of running into an error.
    assert "disabled" in text.split('id="test-mail"')[1][:120]
