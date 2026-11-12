"""Alerting (§8): bundling, throttling, suppression, and that it keeps all of that
across a restart.

No test reaches a real endpoint: `httpx.Client` is replaced by a fake, and on top
of that the loopback block from `conftest.py` holds.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest
from test_enrich_worker import RULESET
from test_scoring_support import make_cert

from ctwatchtower import db, notify
from ctwatchtower.config import settings
from ctwatchtower.pipeline import Pipeline
from ctwatchtower.rules.loader import RuleStore

ZIEL = "https://webhook.example.invalid/ct"


class FakeClient:
    """Replaces `httpx.Client` in the module. Remembers what would have been sent."""

    sent: list[dict] = []
    status = 200
    fehler: Exception | None = None

    def __init__(self, *a, **kw) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a) -> None:
        return None

    def post(self, url, content=None, headers=None):
        if FakeClient.fehler is not None:
            raise FakeClient.fehler
        FakeClient.sent.append(
            {"url": url, "body": json.loads(content), "headers": headers or {}}
        )

        class R:
            status_code = FakeClient.status

        return R()


@pytest.fixture
def pipe(tmp_path, monkeypatch):
    FakeClient.sent = []
    FakeClient.status = 200
    FakeClient.fehler = None
    monkeypatch.setattr(notify.httpx, "Client", FakeClient)
    monkeypatch.setattr(settings, "notify_enabled", True)
    monkeypatch.setattr(settings, "notify_webhook_url", ZIEL)
    monkeypatch.setattr(settings, "notify_secret", "")
    monkeypatch.setattr(settings, "ui_base_url", "https://watchtower.intern")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "banking.yaml").write_text(RULESET, encoding="utf-8")
    p = Pipeline(db.connect(tmp_path / "n.sqlite3"), RuleStore(rules), url="ws://127.0.0.1:1")
    p.rulesets(force=True)
    yield p
    p.conn.close()


def hit(pipe, domain: str) -> dict:
    """Produce a finding through the real pipeline. It offers it to the alerting."""
    events = pipe.process(make_cert([domain]))
    assert events, f"the test setup: {domain} produces no finding"
    return events[0]


# ───────────────────── Two conditions, not one ───────────────────────────


def test_nothing_happens_without_the_switch_and_without_a_target(pipe, monkeypatch) -> None:
    monkeypatch.setattr(settings, "notify_enabled", False)
    assert notify.configured() == (False, "off")
    hit(pipe, "velton-login.com")
    assert pipe.notifier.flush() == 0 and FakeClient.sent == []

    monkeypatch.setattr(settings, "notify_enabled", True)
    monkeypatch.setattr(settings, "notify_webhook_url", "")
    assert notify.configured() == (False, "no target configured")
    hit(pipe, "velton-account.com")
    assert pipe.notifier.flush() == 0 and FakeClient.sent == []


def test_below_the_minimum_severity_nothing_is_reported(pipe, monkeypatch) -> None:
    monkeypatch.setattr(settings, "notify_min_severity", "alert")
    ereignis = hit(pipe, "velton-login.com")
    assert ereignis["severity"] == "warning"
    assert pipe.notifier.flush() == 0


# ──────────────────────────── Bundling (§8.2.1) ──────────────────────────────


def test_many_findings_make_one_message(pipe) -> None:
    for domain in ("velton-login.com", "velton-account.com", "velton-secure.com"):
        hit(pipe, domain)
    assert pipe.notifier.flush() == 3
    assert len(FakeClient.sent) == 1, "one message, not three"

    body = FakeClient.sent[0]["body"]
    assert body["version"] == 1 and body["tenant"] == "banking"
    assert sum(body["counts"].values()) == 3
    assert body["ui_url"].startswith("https://watchtower.intern")
    first = body["findings"][0]
    assert first["matched"], "without a reason the report would be a bare verdict"
    assert first["links"]["crtsh"].startswith("https://crt.sh/")
    # §8.2: descending by score, so that the top hits stand at the top
    points = [f["score"] for f in body["findings"]]
    assert points == sorted(points, reverse=True)


# ───────────────────── Repeat suppression (§8.2.3) ───────────────────────


def test_the_same_domain_is_not_reported_again(pipe) -> None:
    hit(pipe, "velton-login.com")
    assert pipe.notifier.flush() == 1
    pipe.conn.execute("DELETE FROM findings")  # the finding itself is not the point here
    pipe.conn.commit()
    hit(pipe, "velton-login.com")
    assert pipe.notifier.flush() == 0, "no second report inside 7 days"
    assert len(FakeClient.sent) == 1


def test_a_clearly_higher_score_reports_again_after_all(pipe) -> None:
    ereignis = hit(pipe, "velton-login.com")
    pipe.notifier.flush()
    # §8.2.3: the exception, when the score rises by more than `rescore_delta`
    hoeher = dict(ereignis, score=ereignis["score"] + settings.rescore_delta + 5, severity="alert")
    assert pipe.notifier.offer(hoeher) is True
    assert pipe.notifier.flush() == 1


def test_the_suppression_survives_a_restart(pipe, tmp_path) -> None:
    """Otherwise every container start reports the whole wave again."""
    hit(pipe, "velton-login.com")
    assert pipe.notifier.flush() == 1
    path = pipe.conn.execute("PRAGMA database_list").fetchone()["file"]
    pipe.conn.close()

    fresh_pipe = Pipeline(db.connect(path), pipe.store, url="ws://127.0.0.1:1")
    fresh_pipe.rulesets(force=True)
    fresh_pipe.conn.execute("DELETE FROM findings")
    fresh_pipe.conn.commit()
    hit(fresh_pipe, "velton-login.com")
    assert fresh_pipe.notifier.flush() == 0, "the state lies in SQLite, not in memory"
    fresh_pipe.conn.close()


# ─────────────────────── Rate limiting (§8.2.2) ──────────────────────────


def test_more_than_twelve_messages_an_hour_are_slowed_down(pipe, monkeypatch) -> None:
    monkeypatch.setattr(settings, "notify_max_per_hour", 2)
    for i in range(3):
        hit(pipe, f"velton-{i}-login.com")
        pipe.notifier.flush()
    assert len(FakeClient.sent) == 2, "the third message is held back"
    assert pipe.notifier.suppressed >= 1

    # An hour later there is room again
    old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    pipe.conn.execute("UPDATE notify_log SET sent_at=?", (old,))
    pipe.conn.commit()
    hit(pipe, "velton-danach-login.com")
    assert pipe.notifier.flush() == 1


# ───────────────────────────── Zustellung ─────────────────────────────


def test_a_signature_when_a_secret_is_set(pipe, monkeypatch) -> None:
    monkeypatch.setattr(settings, "notify_secret", "s3cr3t")
    hit(pipe, "velton-login.com")
    pipe.notifier.flush()
    message = FakeClient.sent[0]
    erwartet = hmac.new(b"s3cr3t", json.dumps(message["body"], ensure_ascii=False).encode(),
                        hashlib.sha256).hexdigest()
    assert message["headers"]["X-Watchtower-Signature"] == erwartet


def test_a_failed_delivery_marks_the_channel_as_stuck(pipe, monkeypatch) -> None:
    monkeypatch.setattr(notify, "RETRY_DELAYS", ())  # no waiting in the test
    FakeClient.status = 500
    hit(pipe, "velton-login.com")
    assert pipe.notifier.flush() == 0
    assert pipe.notifier.degraded is True and pipe.notifier.failed == 1
    assert pipe.notifier.status()["state"] == "degraded"
    # The finding stays unreported. Next time it may try again
    assert pipe.conn.execute("SELECT COUNT(*) FROM notify_state").fetchone()[0] == 0


def test_the_status_says_what_the_matter_is(pipe, monkeypatch) -> None:
    assert pipe.notifier.status()["state"] == "ready"
    monkeypatch.setattr(settings, "notify_webhook_url", "")
    assert pipe.notifier.status()["state"] == "no target configured"
    monkeypatch.setattr(settings, "notify_enabled", False)
    assert pipe.notifier.status()["state"] == "off"


def test_an_upgrade_after_the_enrichment_is_reported(pipe, monkeypatch) -> None:
    """§7.9: what the enrichment upgrades is a report of its own."""
    ereignis = hit(pipe, "velton-login.com")
    assert pipe.notifier.flush() == 1  # the first report is not the point here
    FakeClient.sent.clear()
    pipe.conn.execute(
        "UPDATE findings SET score=?, severity='alert' WHERE id=?",
        (ereignis["score"] + 20, ereignis["id"]),
    )
    pipe.conn.commit()
    hochgestuft = dict(ereignis, action="escalate", score=ereignis["score"] + 20, severity="alert")
    assert pipe.notifier.offer(hochgestuft) is True
    assert pipe.notifier.flush() == 1
    assert FakeClient.sent[0]["body"]["counts"] == {"alert": 1}


def test_the_system_screen_shows_the_channel(tmp_path, monkeypatch) -> None:
    """§8.2.6: a stuck channel has to be visible, otherwise you wait for nothing."""
    from ctwatchtower.app import create_app

    monkeypatch.setattr(settings, "notify_enabled", False)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "banking.yaml").write_text(RULESET, encoding="utf-8")
    app = create_app(db_path=tmp_path / "s.sqlite3", rules_dir=rules, start_pipeline=False)
    try:
        seite = app.test_client().get("/ui/system").get_data(as_text=True)
        # Do not check for the name of the environment variable: since the settings
        # page exists it is switched on in the interface. What has to be shown is
        # the state and the way there.
        assert "Alerting" in seite and "Switched off" in seite
        assert "/settings" in seite
    finally:
        app.config["DB"].close()


# ──────────────────── Two channels, one brake ───────────────────────────


def _mail_on(monkeypatch, sent: list) -> None:
    """Set up email and replace the sending with a fake.

    Nothing is sent: `mail.send` is replaced before any connection could come
    about at all.
    """
    from ctwatchtower.notify import mail

    monkeypatch.setattr(settings, "mail_enabled", True)
    monkeypatch.setattr(settings, "mail_from", "watchtower@beispiel.invalid")
    monkeypatch.setattr(settings, "mail_to", "security@beispiel.invalid")
    monkeypatch.setattr(settings, "mail_smtp_host", "mail.beispiel.invalid")
    monkeypatch.setattr(mail, "send", lambda b, t: sent.append((b, t)))


def test_the_mail_gets_the_same_summary_as_the_webhook(pipe, monkeypatch) -> None:
    mails: list = []
    _mail_on(monkeypatch, mails)
    hit(pipe, "velton-login.com")
    assert pipe.notifier.flush() == 1

    assert len(FakeClient.sent) == 1, "the webhook has to keep being served"
    assert len(mails) == 1, "and the mail on top of it"
    subject, text = mails[0]
    assert "banking" in subject
    assert "velton-login[.]com" in text


def test_one_mail_per_window_not_one_per_finding(pipe, monkeypatch) -> None:
    """The same brake as on the webhook: a wave produces **one** message.
    Anyone who gets flooded switches the reports off."""
    mails: list = []
    _mail_on(monkeypatch, mails)
    for d in ("velton-login.com", "velton-account.com", "velton-secure.com"):
        hit(pipe, d)
    pipe.notifier.flush()
    assert len(mails) == 1


def test_without_a_webhook_the_mail_suffices(pipe, monkeypatch) -> None:
    """Anyone who only wants mail should not have to invent a webhook."""
    mails: list = []
    monkeypatch.setattr(settings, "notify_webhook_url", "")
    _mail_on(monkeypatch, mails)
    assert notify.configured()[0] is True
    hit(pipe, "velton-login.com")
    assert pipe.notifier.flush() == 1
    assert len(mails) == 1 and FakeClient.sent == []


def test_one_broken_channel_lets_the_other_deliver(pipe, monkeypatch) -> None:
    """Otherwise a broken webhook would defeat the repeat suppression and the same
    findings would arrive by mail again and again."""
    mails: list = []
    _mail_on(monkeypatch, mails)
    FakeClient.status = 500                      # the webhook does not answer
    monkeypatch.setattr(pipe.stop_event, "wait", lambda s: True)   # no waiting

    hit(pipe, "velton-login.com")
    assert pipe.notifier.flush() == 1, "the mail got through, so it counts as delivered"
    assert len(mails) == 1

    state = pipe.notifier.status()
    assert state["state"] == "ready"
    channels = {k["kind"]: k["degraded"] for k in state["channels"]}
    assert channels == {"webhook": True, "mail": False}


def test_if_the_mail_fails_it_counts_as_stuck(pipe, monkeypatch) -> None:
    from ctwatchtower.notify import mail

    monkeypatch.setattr(settings, "mail_enabled", True)
    monkeypatch.setattr(settings, "mail_from", "watchtower@beispiel.invalid")
    monkeypatch.setattr(settings, "mail_to", "security@beispiel.invalid")
    monkeypatch.setattr(settings, "mail_smtp_host", "mail.beispiel.invalid")

    def platzt(subject, text):
        raise RuntimeError("the login was refused")

    monkeypatch.setattr(mail, "send", platzt)
    hit(pipe, "velton-login.com")
    # The webhook accepts, so the message is out; the mail is stuck all the same.
    assert pipe.notifier.flush() == 1
    channels = {k["kind"]: k["degraded"] for k in pipe.notifier.status()["channels"]}
    assert channels["mail"] is True
