"""Mail as a second alerting route.

**Nothing is sent here and nothing is connected.** Every test replaces the sending
route with a fake and checks what was built, not whether it arrives. Whether it
arrives can only be established by the operator with their own credentials; that is
what the "send a test message" button on the system screen is for.

`tests/conftest.py` only allows loopback anyway: a test that accidentally talks to a
mail server fails on the network instead of producing a mail.
"""

from __future__ import annotations

import pytest

from ctwatchtower.config import settings
from ctwatchtower.notify import mail


@pytest.fixture
def set_up(monkeypatch):
    """A fully entered SMTP route, without that route existing."""
    for field, value in {
        "mail_enabled": True,
        "mail_transport": "smtp",
        "mail_from": "watchtower@example.invalid",
        "mail_to": "security@example.invalid, second@example.invalid",
        "mail_smtp_host": "mail.example.invalid",
    }.items():
        monkeypatch.setattr(settings, field, value)
    return settings


EXAMPLE = {
    "tenant": "Velton Ltd",
    "window_seconds": 300,
    "counts": {"alert": 2, "warning": 1},
    "ui_url": "https://watchtower.internal/findings?t=velton",
    "findings": [
        {"domain": "velton-login.top", "score": 92, "matched": ["anchor:velton", "lure:login"]},
        {"domain": "veltonportal.my", "score": 45, "matched": ["anchor:velton"]},
    ],
    "truncated": 7,
}


# ------------------------------- Setup -------------------------------


def test_without_the_switch_nothing_happens():
    """As with the webhook: a switch **and** a target. Otherwise something goes out
    by accident."""
    assert mail.configured() == (False, "off")


@pytest.mark.parametrize(
    "missing,expected",
    [
        ("mail_from", "sender or recipient missing"),
        ("mail_to", "sender or recipient missing"),
        ("mail_smtp_host", "no SMTP server entered"),
    ],
)
def test_every_gap_is_named(set_up, monkeypatch, missing, expected):
    """The reason ends up on the system screen. "Not set up" alone helps nobody
    looking for it."""
    monkeypatch.setattr(settings, missing, "")
    ok, reason = mail.configured()
    assert not ok and reason == expected


def test_an_unknown_provider_names_the_possible_ones(set_up, monkeypatch):
    monkeypatch.setattr(settings, "mail_transport", "http")
    monkeypatch.setattr(settings, "mail_http_provider", "myprovider")
    ok, reason = mail.configured()
    assert not ok
    assert "brevo" in reason and "postmark" in reason


def test_mailgun_demands_its_domain(set_up, monkeypatch):
    """Mailgun carries the sender domain in the path. Without it the request goes
    nowhere."""
    monkeypatch.setattr(settings, "mail_transport", "http")
    monkeypatch.setattr(settings, "mail_http_provider", "mailgun_eu")
    monkeypatch.setattr(settings, "mail_http_key", "key-xyz")
    assert mail.configured() == (False, "Mailgun needs the registered sender domain")
    monkeypatch.setattr(settings, "mail_http_domain", "mg.example.invalid")
    assert mail.configured() == (True, "ready")


def test_recipients_are_split_at_the_comma(set_up):
    assert mail.recipients() == ["security@example.invalid", "second@example.invalid"]


# --------------------------- What is in the mail ---------------------------


def test_the_subject_carries_the_numbers():
    """Only the subject shows up in the inbox. "alert" alone does not say whether it
    is one or forty."""
    assert mail.subject(EXAMPLE) == "CT-Watchtower - Velton Ltd: 2 alert, 1 warning"


def test_domains_appear_defanged_in_the_mail():
    """The name ends up in an inbox where somebody clicks out of habit. `[.]` turns
    it into text instead of a target."""
    text = mail.text(EXAMPLE)
    assert "velton-login[.]top" in text
    assert "velton-login.top" not in text


def test_the_mail_explains_itself():
    text = mail.text(EXAMPLE)
    assert "2  alert" in text and "1  warning" in text
    assert "anchor:velton, lure:login" in text      # the reason, not just the score
    assert "and 7 more" in text                     # what did not fit into the mail
    assert "https://watchtower.internal/findings?t=velton" in text
    # The attitude of the product belongs in every alert somebody reads at 3 am.
    assert "worth checking" in text and 'not "malicious"' in text


def test_no_links_to_the_suspicious_domain():
    """An `http://` link to the finding would be one click away from the site."""
    text = mail.text(EXAMPLE)
    for row in text.splitlines():
        if "velton-login" in row:
            assert "http" not in row, row


def test_the_headers_prevent_out_of_office_replies(set_up):
    msg = mail._message("Subject", "Body")
    assert msg["Auto-Submitted"] == "auto-generated"
    assert msg["To"] == "security@example.invalid, second@example.invalid"
    assert msg["Message-ID"].endswith("@example.invalid>")


# --------------------------- Routes, with a fake ---------------------------


def test_the_smtp_route_connects_as_configured(set_up, monkeypatch):
    """What is checked is the order: connect, STARTTLS, log in, send. Nothing is
    connected while doing it. `smtplib.SMTP` is a fake."""
    log = []

    class Fake:
        def __init__(self, host, port, timeout=None):
            log.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            log.append(("close",))

        def starttls(self, context=None):
            log.append(("starttls", context is not None))

        def login(self, user, pw):
            log.append(("login", user))

        def send_message(self, msg):
            log.append(("send", msg["Subject"]))

    monkeypatch.setattr(settings, "mail_smtp_user", "watchtower")
    monkeypatch.setattr(settings, "mail_smtp_password", "secret")
    monkeypatch.setattr("ctwatchtower.notify.mail.smtplib.SMTP", Fake)

    mail.send("Subject", "Body")
    assert log == [
        ("connect", "mail.example.invalid", 587),
        ("starttls", True),
        ("login", "watchtower"),
        ("send", "Subject"),
        ("close",),
    ]


def test_without_credentials_there_is_no_login(set_up, monkeypatch):
    """A relay in your own network often accepts without a login, and then none may
    be attempted."""
    log = []

    class Fake:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def starttls(self, context=None):
            pass

        def login(self, *a):
            log.append("login")

        def send_message(self, msg):
            log.append("send")

    monkeypatch.setattr("ctwatchtower.notify.mail.smtplib.SMTP", Fake)
    mail.send("Subject", "Body")
    assert log == ["send"]


@pytest.mark.parametrize(
    "provider,expected_in_url,header",
    [
        ("brevo", "api.brevo.com", "api-key"),
        ("postmark", "postmarkapp.com", "X-Postmark-Server-Token"),
        ("resend", "api.resend.com", "Authorization"),
        ("sendgrid", "sendgrid.com", "Authorization"),
    ],
)
def test_the_http_route_talks_to_the_right_provider(
    set_up, monkeypatch, provider, expected_in_url, header
):
    """The HTTPS route exists because many networks block the SMTP ports. What is
    checked is what **would** be sent. The request does not leave the machine."""
    sent = {}

    class FakeClient:
        def __init__(self, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def post(self, url, headers=None, auth=None, json=None, data=None):
            sent.update(url=url, headers=headers, auth=auth, json=json, data=data)

            class Answer:
                status_code = 200
                text = ""

            return Answer()

    monkeypatch.setattr(settings, "mail_transport", "http")
    monkeypatch.setattr(settings, "mail_http_provider", provider)
    monkeypatch.setattr(settings, "mail_http_key", "key-123")
    monkeypatch.setattr("ctwatchtower.notify.mail.httpx.Client", FakeClient)

    mail.send("Subject", "Body")
    assert expected_in_url in sent["url"]
    assert header in sent["headers"]
    assert "key-123" in sent["headers"][header]
    # Subject and recipient have to arrive in the body, whatever the provider calls it.
    body = str(sent["json"])
    assert "Subject" in body and "security@example.invalid" in body


def test_mailgun_goes_form_encoded_with_basic_auth(set_up, monkeypatch):
    """Mailgun is the only one that differs. That has to be in a test, otherwise it
    only shows up on the first real alert."""
    sent = {}

    class FakeClient:
        def __init__(self, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def post(self, url, headers=None, auth=None, json=None, data=None):
            sent.update(url=url, auth=auth, json=json, data=data)

            class Answer:
                status_code = 200
                text = ""

            return Answer()

    monkeypatch.setattr(settings, "mail_transport", "http")
    monkeypatch.setattr(settings, "mail_http_provider", "mailgun_eu")
    monkeypatch.setattr(settings, "mail_http_key", "key-abc")
    monkeypatch.setattr(settings, "mail_http_domain", "mg.example.invalid")
    monkeypatch.setattr("ctwatchtower.notify.mail.httpx.Client", FakeClient)

    mail.send("Subject", "Body")
    assert sent["url"] == "https://api.eu.mailgun.net/v3/mg.example.invalid/messages"
    assert sent["auth"] == ("api", "key-abc")
    assert sent["json"] is None and sent["data"]["subject"] == "Subject"


def test_a_provider_error_comes_back_in_plain_text(set_up, monkeypatch):
    """A bare "401" does not say whether the key is wrong or the sender address is
    not cleared."""

    class FakeClient:
        def __init__(self, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def post(self, *a, **k):
            class Answer:
                status_code = 401
                text = "sender address not verified"

            return Answer()

    monkeypatch.setattr(settings, "mail_transport", "http")
    monkeypatch.setattr(settings, "mail_http_provider", "resend")
    monkeypatch.setattr(settings, "mail_http_key", "key")
    monkeypatch.setattr("ctwatchtower.notify.mail.httpx.Client", FakeClient)

    with pytest.raises(RuntimeError, match="sender address not verified"):
        mail.send("Subject", "Body")


def test_sending_without_setup_raises_instead_of_failing_quietly():
    with pytest.raises(RuntimeError, match="off"):
        mail.send("Subject", "Body")
