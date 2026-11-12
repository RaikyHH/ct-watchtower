"""Triggering an analysis at an external scanner.

No test talks to a real service. `conftest` blocks sockets, and every test here
brings its own fake. Both providers require in their terms that you are allowed to
scan the address; a test suite firing off real submissions in bulk would be exactly
what they forbid.
"""

from __future__ import annotations

import threading

import httpx
import pytest
from conftest import copy_rule_base

from ctwatchtower.config import settings
from ctwatchtower.db import connect
from ctwatchtower.enrich.net import Defer, Quota, Transient
from ctwatchtower.enrich.scan import SERVICES, ScanError, submit


@pytest.fixture(autouse=True)
def _switched_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "scan_enabled", True)
    monkeypatch.setattr(settings, "scan_visibility", "private")
    monkeypatch.setattr(settings, "scan_daily", 25)
    monkeypatch.setattr(settings, "urlscan_api_key", "key")
    monkeypatch.setattr(settings, "scanmalware_api_key", "key")


def fake(response: httpx.Response | Exception, seen: list | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if isinstance(response, Exception):
            raise response
        return response

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_urlscan_gets_visibility_and_the_key_header() -> None:
    seen: list[httpx.Request] = []
    response = httpx.Response(200, json={"uuid": "abc", "result": "https://urlscan.io/result/abc/"})
    http = fake(response, seen)
    result = submit("evil.example", "urlscan", http=http)

    (request,) = seen
    assert str(request.url) == "https://urlscan.io/api/v1/scan/"
    assert request.headers["API-Key"] == "key"
    import json

    assert json.loads(request.content) == {"url": "https://evil.example", "visibility": "private"}
    assert result == {
        "service": "urlscan",
        "scan_id": "abc",
        "result": "https://urlscan.io/result/abc/",
        "visibility": "private",
        "submitted_at": "",
    }


def test_scanmalware_calls_the_field_something_else() -> None:
    """The two services call the same field by different names, which is the whole
    reason for the service table. Swap them and you scan publicly instead of
    privately."""
    seen: list[httpx.Request] = []
    http = fake(httpx.Response(200, json={"scan_id": "xyz", "status": "queued"}), seen)
    result = submit("evil.example", "scanmalware", http=http)

    import json

    payload = json.loads(seen[0].content)
    assert payload["scan_type"] == "private" and "visibility" not in payload
    assert seen[0].headers["X-API-Key"] == "key"
    # Without `result` in the answer the pattern takes over.
    assert result["result"] == "https://scanmalware.com/result/xyz"


def test_only_the_bare_name_is_submitted() -> None:
    """Nothing from the certificate may end up in the URL. No path, no parameter."""
    seen: list[httpx.Request] = []
    http = fake(httpx.Response(200, json={"scan_id": "1"}), seen)
    submit("evil.example", "scanmalware", http=http)
    import json

    assert json.loads(seen[0].content)["url"] == "https://evil.example"


def test_switched_off_submits_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "scan_enabled", False)
    seen: list[httpx.Request] = []
    with pytest.raises(ScanError, match="switched off"):
        submit("evil.example", "scanmalware", http=fake(httpx.Response(200), seen))
    assert seen == []  # the switch applies BEFORE the network call


def test_an_unknown_service_is_refused() -> None:
    with pytest.raises(ScanError, match="unknown service"):
        submit("evil.example", "made-up")


def test_private_without_a_key_does_not_work(monkeypatch: pytest.MonkeyPatch) -> None:
    # scanmalware can do public/unlisted without a key. Private it cannot. Quietly
    # falling back to public would be the worst of it: the finding would be given away.
    monkeypatch.setattr(settings, "scanmalware_api_key", None)
    seen: list[httpx.Request] = []
    with pytest.raises(ScanError, match="API key"):
        submit("evil.example", "scanmalware", http=fake(httpx.Response(200), seen))
    assert seen == []

    # Unlisted works there without one.
    http = fake(httpx.Response(200, json={"scan_id": "1"}))
    open_scan = submit("evil.example", "scanmalware", visibility="unlisted", http=http)
    assert open_scan["visibility"] == "unlisted"


def test_urlscan_always_needs_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "urlscan_api_key", None)
    with pytest.raises(ScanError, match="API key"):
        submit("evil.example", "urlscan", visibility="public", http=fake(httpx.Response(200)))


def test_an_unknown_visibility_is_refused() -> None:
    seen: list[httpx.Request] = []
    with pytest.raises(ScanError, match="visibility"):
        submit(
            "evil.example", "urlscan", visibility="semi-public",
            http=fake(httpx.Response(200), seen),
        )
    assert seen == []


@pytest.mark.parametrize(
    ("status", "error"),
    [(429, Defer), (500, Transient), (503, Transient), (400, ScanError), (403, ScanError)],
)
def test_error_kinds(status: int, error: type[Exception]) -> None:
    with pytest.raises(error):
        submit("evil.example", "urlscan", http=fake(httpx.Response(status, text="no")))


def test_a_network_error_is_temporary() -> None:
    with pytest.raises(Transient):
        submit("evil.example", "urlscan", http=fake(httpx.ConnectError("gone")))


def test_an_answer_without_an_id_is_an_error() -> None:
    with pytest.raises(ScanError, match="scan id"):
        submit("evil.example", "urlscan", http=fake(httpx.Response(200, json={"message": "ok"})))


def test_a_foreign_result_url_is_not_taken_over() -> None:
    """The service sends the result URL along. It ends up as a link in the UI, so
    nothing that is not `https` may stand there."""
    http = fake(httpx.Response(200, json={"uuid": "abc", "result": "javascript:alert(1)"}))
    assert submit("evil.example", "urlscan", http=http)["result"] == "https://urlscan.io/result/abc/"


def test_the_daily_cap_applies_before_the_network_call(tmp_path) -> None:
    conn = connect(tmp_path / "t.sqlite3")
    try:
        quota = Quota(conn, threading.Lock())
        seen: list[httpx.Request] = []
        response = httpx.Response(200, json={"scan_id": "1"})
        for _ in range(3):
            submit("evil.example", "scanmalware", quota=quota, http=fake(response, seen))
        assert len(seen) == 3

        settings.scan_daily = 3
        with pytest.raises(Defer):
            submit("evil.example", "scanmalware", quota=quota, http=fake(response, seen))
        assert len(seen) == 3  # nothing went out

        # The cap counts per service: the other one has a budget of its own.
        other = fake(httpx.Response(200, json={"uuid": "a"}), seen)
        submit("evil.example", "urlscan", quota=quota, http=other)
        assert len(seen) == 4
    finally:
        conn.close()


def test_there_is_no_bulk_call() -> None:
    """The user's requirement: manual only, for a single finding only. If somebody
    adds a bulk function later, this test should notice."""
    import inspect

    import ctwatchtower.enrich.scan as module

    own = {
        n: f for n, f in vars(module).items()
        if inspect.isfunction(f) and f.__module__ == module.__name__ and not n.startswith("_")
    }
    assert set(own) == {"submit", "is_ready"}
    # The point is not the number of functions but that none of them takes a list:
    # every call concerns exactly one name, exactly one scan.
    for name, f in own.items():
        first = next(iter(inspect.signature(f).parameters.values()))
        assert first.annotation == "str", f"{name} takes {first.annotation} instead of a name"
    assert next(iter(inspect.signature(own["submit"]).parameters)) == "domain"


# ---------------------------- through the API ----------------------------


def app_with_finding(tmp_path) -> tuple:
    from test_scoring_support import make_cert

    from ctwatchtower import db
    from ctwatchtower.app import create_app
    from ctwatchtower.normalize.names import normalize

    rules = copy_rule_base(tmp_path / "rules")
    app = create_app(db_path=tmp_path / "t.sqlite3", rules_dir=rules, start_pipeline=False)
    conn = app.config["DB"]
    conn.execute("INSERT INTO tenants (id, name) VALUES ('t', 'T')")
    fid, _ = db.upsert_finding(
        conn, "t", normalize("evil-example.top"), make_cert(["evil-example.top"]),
        score=90, severity="alert", explanation={"matched": ["anchor:evil"]},
    )
    conn.commit()
    return app, fid


def test_the_api_refuses_an_unknown_service_and_an_unknown_finding(tmp_path) -> None:
    app, fid = app_with_finding(tmp_path)
    try:
        client_ = app.test_client()
        assert client_.post(f"/api/v1/findings/{fid}/scan",
                            json={"service": "made-up"}).status_code == 400
        assert client_.post(f"/api/v1/findings/{fid}/scan", json={}).status_code == 400
        # The finding does not exist: 404, not "switched off".
        response = client_.post("/api/v1/findings/nosuchthing/scan", json={"service": "urlscan"})
        assert response.status_code == 404 and response.get_json()["status"] == "unknown"
    finally:
        app.config["DB"].close()


def test_the_api_reports_disabled_instead_of_scanning(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "scan_enabled", False)
    app, fid = app_with_finding(tmp_path)
    try:
        response = app.test_client().post(f"/api/v1/findings/{fid}/scan",
                                          json={"service": "urlscan"})
        assert response.status_code == 409 and response.get_json()["status"] == "disabled"
    finally:
        app.config["DB"].close()


def test_the_api_stores_the_result_on_the_finding(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "ctwatchtower.pipeline.submit",
        lambda domain, service, **kw: {
            "service": service, "scan_id": "abc", "result": "https://urlscan.io/result/abc/",
            "visibility": "private", "submitted_at": "",
        },
    )
    app, fid = app_with_finding(tmp_path)
    try:
        client_ = app.test_client()
        response = client_.post(f"/api/v1/findings/{fid}/scan", json={"service": "urlscan"})
        assert response.status_code == 200 and response.get_json()["scan"]["scan_id"] == "abc"

        # The link survives. Otherwise you would have to submit again after a restart.
        hit = client_.get(f"/api/v1/findings/{fid}").get_json()
        assert hit["scans"]["urlscan"]["result"] == "https://urlscan.io/result/abc/"

        # A second service sits next to the first instead of pushing it out.
        client_.post(f"/api/v1/findings/{fid}/scan", json={"service": "scanmalware"})
        assert set(client_.get(f"/api/v1/findings/{fid}").get_json()["scans"]) == {
            "urlscan", "scanmalware"}
    finally:
        app.config["DB"].close()


def test_both_services_are_wired_up() -> None:
    assert set(SERVICES) == {"urlscan", "scanmalware"}
    assert all(s.endpoint.startswith("https://") for s in SERVICES.values())


# --------------------- Is the result there yet? ---------------------------
#
# urlscan only creates the result page once the scan is through. Until then it
# answers 404. That is no fault, it is the answer "still running". Treat it as an
# error and you show the user a dead link.


def test_four_oh_four_means_still_running_not_broken() -> None:
    from ctwatchtower.enrich.scan import is_ready

    assert is_ready("urlscan", "abc", http=fake(httpx.Response(404))) == {"state": "running"}


def test_two_hundred_means_done() -> None:
    from ctwatchtower.enrich.scan import is_ready

    response = httpx.Response(200, json={"task": {"uuid": "abc"}})
    assert is_ready("urlscan", "abc", http=fake(response))["state"] == "done"


def test_the_query_carries_the_key_and_asks_the_right_address() -> None:
    """Private scans cannot even be polled for without a key."""
    from ctwatchtower.enrich.scan import is_ready

    seen: list[httpx.Request] = []
    is_ready("urlscan", "abc", http=fake(httpx.Response(404), seen))
    assert str(seen[0].url) == "https://urlscan.io/api/v1/result/abc/"
    assert seen[0].headers["API-Key"] == "key"
    assert seen[0].method == "GET"


def test_a_deleted_result_ends_the_asking() -> None:
    """A 410 can come at any time, even right after submitting. Carrying on asking
    would be pointless load for somebody else's service."""
    from ctwatchtower.enrich.scan import is_ready

    assert is_ready("urlscan", "abc", http=fake(httpx.Response(410)))["state"] == "deleted"


def test_throttling_passes_the_services_wait_through() -> None:
    from ctwatchtower.enrich.scan import is_ready

    response = httpx.Response(429, headers={"X-Rate-Limit-Reset-After": "42"})
    result = is_ready("urlscan", "abc", http=fake(response))
    assert result["state"] == "throttled"
    assert result["retry_after"] == 42.0


def test_a_network_blip_is_no_verdict_about_the_scan() -> None:
    """The scan carries on at the service even when we cannot reach it right now."""
    from ctwatchtower.enrich.scan import is_ready

    error = httpx.ConnectError("gone")
    assert is_ready("urlscan", "abc", http=fake(error))["state"] == "running"


def test_a_service_without_a_status_endpoint_fakes_no_readiness() -> None:
    """scanmalware has no such endpoint. Then the UI says nothing instead of showing
    an hourglass that never stops."""
    from ctwatchtower.enrich.scan import is_ready

    assert is_ready("scanmalware", "abc") == {"state": "unknown"}


def test_the_whole_way_from_trigger_to_finished_result(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Trigger -> hourglass -> done, seen through the API.

    That is the sequence the user lives through: the link to the result may only be
    offered once the service has something to show.
    """
    from ctwatchtower.enrich import scan as scan_module

    app, fid = app_with_finding(tmp_path)
    client_ = app.test_client()
    try:
        monkeypatch.setattr(
            scan_module, "submit",
            lambda *a, **k: {"service": "urlscan", "scan_id": "abc", "visibility": "private",
                             "result": "https://urlscan.io/result/abc/", "submitted_at": ""},
        )
        import ctwatchtower.pipeline as pl
        monkeypatch.setattr(pl, "submit", scan_module.submit)

        triggered = client_.post(f"/api/v1/findings/{fid}/scan", json={"service": "urlscan"})
        assert triggered.status_code == 200
        assert triggered.get_json()["scan"]["state"] == "running", \
            "right after triggering it is running"

        # First poll: the service is not there yet.
        monkeypatch.setattr(pl, "scan_ready", lambda *a, **k: {"state": "running"})
        assert client_.get(
            f"/api/v1/findings/{fid}/scan/urlscan").get_json()["state"] == "running"

        # Second poll: done.
        monkeypatch.setattr(pl, "scan_ready", lambda *a, **k: {"state": "done"})
        done = client_.get(f"/api/v1/findings/{fid}/scan/urlscan").get_json()
        assert done["state"] == "done"
        assert done["result"] == "https://urlscan.io/result/abc/"

        # Once the state is final the service is not asked again.
        def must_not(*a, **k):
            raise AssertionError("a finished scan is not polled for again")

        monkeypatch.setattr(pl, "scan_ready", must_not)
        assert client_.get(f"/api/v1/findings/{fid}/scan/urlscan").get_json()["state"] == "done"
    finally:
        app.config["DB"].close()


def test_the_polling_stops_eventually(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A window left open must not keep somebody else's service busy forever."""
    import ctwatchtower.pipeline as pl
    from ctwatchtower.enrich import scan as scan_module

    app, fid = app_with_finding(tmp_path)
    client_ = app.test_client()
    try:
        monkeypatch.setattr(
            pl, "submit",
            lambda *a, **k: {"service": "urlscan", "scan_id": "abc", "visibility": "private",
                             "result": "https://urlscan.io/result/abc/", "submitted_at": ""},
        )
        client_.post(f"/api/v1/findings/{fid}/scan", json={"service": "urlscan"})

        asked = []
        monkeypatch.setattr(pl, "scan_ready",
                            lambda *a, **k: (asked.append(1), {"state": "running"})[1])
        for _ in range(scan_module.MAX_POLLS + 5):
            latest = client_.get(f"/api/v1/findings/{fid}/scan/urlscan").get_json()

        assert len(asked) == scan_module.MAX_POLLS, "past the limit it stops asking"
        assert latest["state"] == "unknown"
    finally:
        app.config["DB"].close()
