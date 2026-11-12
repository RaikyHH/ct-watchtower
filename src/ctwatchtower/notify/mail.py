"""Mail as a second alerting route next to the webhook (§8.1).

**Two routes, because one of them often does not work.** `smtp` is the obvious one:
enter the credentials of your own or a rented mail server and you are done. Only
many networks block ports 25, 465 and 587. On home lines almost always, in data
centres often. Then `http` is left: the same providers also take mail over their
HTTPS interface, and port 443 is open everywhere.

**No SSRF protection, and that is on purpose.** The enrichment talks to servers a
third party picks, and there `enrich/net.py` filters out everything that is not
publicly routable. Here it is the other way round: the target is picked by whoever
runs the application, and a mail relay in your own network (`10.0.0.25`) is the
normal case, not an attack.

**What is in the mail.** The same summary as in the webhook: how many findings per
severity, the strongest ones with score and reason, a link into the UI. No images,
no tracking pixels, no links to the suspicious domain itself, which would otherwise
sit clickable in somebody's inbox.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

import httpx

from ctwatchtower.config import settings

log = logging.getLogger(__name__)

# Providers with an HTTPS interface. Built like `enrich/scan.py`: one line per
# provider, no code. Whoever needs another one enters it here.
#
#   url      endpoint
#   auth     ("header", name, template) or ("basic", user)
#   body     builds the body from (sender, recipients, subject, text)
#   form     True = form-encoded instead of JSON (Mailgun only)
PROVIDERS: dict[str, dict[str, Any]] = {
    "brevo": {
        "url": "https://api.brevo.com/v3/smtp/email",
        "auth": ("header", "api-key", "{key}"),
        "body": lambda a, e, b, t: {
            "sender": {"email": a},
            "to": [{"email": x} for x in e],
            "subject": b,
            "textContent": t,
        },
    },
    "postmark": {
        "url": "https://api.postmarkapp.com/email",
        "auth": ("header", "X-Postmark-Server-Token", "{key}"),
        "body": lambda a, e, b, t: {
            "From": a, "To": ",".join(e), "Subject": b, "TextBody": t,
            "MessageStream": "outbound",
        },
    },
    "resend": {
        "url": "https://api.resend.com/emails",
        "auth": ("header", "Authorization", "Bearer {key}"),
        "body": lambda a, e, b, t: {"from": a, "to": e, "subject": b, "text": t},
    },
    "sendgrid": {
        "url": "https://api.sendgrid.com/v3/mail/send",
        "auth": ("header", "Authorization", "Bearer {key}"),
        "body": lambda a, e, b, t: {
            "personalizations": [{"to": [{"email": x} for x in e]}],
            "from": {"email": a},
            "subject": b,
            "content": [{"type": "text/plain", "value": t}],
        },
    },
    # Mailgun wants form encoding and carries the sender domain in the path.
    "mailgun": {
        "url": "https://api.mailgun.net/v3/{domain}/messages",
        "auth": ("basic", "api"),
        "form": True,
        "body": lambda a, e, b, t: {"from": a, "to": e, "subject": b, "text": t},
    },
    "mailgun_eu": {
        "url": "https://api.eu.mailgun.net/v3/{domain}/messages",
        "auth": ("basic", "api"),
        "form": True,
        "body": lambda a, e, b, t: {"from": a, "to": e, "subject": b, "text": t},
    },
}


def recipients() -> list[str]:
    """The recipient list. Several of them separated by commas."""
    return [a.strip() for a in settings.mail_to.split(",") if a.strip()]


def configured() -> tuple[bool, str]:
    """Whether mail may be sent, and if not, what is missing.

    As with the webhook: a switch **and** a target. The answer ends up on the system
    screen, so nobody waits for alerts that never come.
    """
    if not settings.mail_enabled:
        return False, "off"
    if not settings.mail_from or not recipients():
        return False, "sender or recipient missing"
    if settings.mail_transport == "smtp":
        if not settings.mail_smtp_host:
            return False, "no SMTP server entered"
        return True, "ready"
    if settings.mail_transport == "http":
        provider = PROVIDERS.get(settings.mail_http_provider)
        if provider is None:
            possible = ", ".join(sorted(PROVIDERS))
            return False, f"unknown provider, possible are: {possible}"
        if not settings.mail_http_key:
            return False, "no key for the provider"
        if "{domain}" in provider["url"] and not settings.mail_http_domain:
            return False, "Mailgun needs the registered sender domain"
        return True, "ready"
    return False, f"unknown route '{settings.mail_transport}', smtp or http"


def subject(data: dict[str, Any]) -> str:
    """What shows up in the inbox list. The numbers, not just "alert"."""
    parts = [
        f"{n} {word}"
        for severity, word in (("alert", "alert"), ("warning", "warning"), ("info", "info"))
        if (n := data["counts"].get(severity))
    ]
    return f"CT-Watchtower - {data['tenant']}: " + (", ".join(parts) or "new findings")


def text(data: dict[str, Any]) -> str:
    """The body as plain text.

    Deliberately without HTML: an alert about phishing that looks like a marketing
    mail itself is a bad alert. And plain text cannot load tracking pixels.
    """
    rows = [
        f"{data['tenant']}, new findings in a window of "
        f"{int(data['window_seconds'] / 60)} minutes.",
        "",
    ]
    for severity, word in (("alert", "alert"), ("warning", "warning"), ("info", "info")):
        if n := data["counts"].get(severity):
            rows.append(f"  {n:>4}  {word}")
    rows += ["", "The strongest ones:", ""]
    for f in data["findings"]:
        # The name defanged: it sits in an inbox where somebody clicks out of habit.
        # `[.]` turns it into text instead of a target.
        name = str(f["domain"]).replace(".", "[.]")
        reason = ", ".join(f.get("matched") or []) or "-"
        rows.append(f"  {f.get('score'):>3}  {name}")
        rows.append(f"       {reason}")
    if data.get("truncated"):
        rows.append(f"  ... and {data['truncated']} more.")
    if data.get("ui_url"):
        rows += ["", f"See all of them: {data['ui_url']}"]
    rows += [
        "",
        "A high score means \"worth checking\", not \"malicious\". There are legitimate",
        "reasons for brand-like domains: partners, resellers, fan sites, criticism.",
    ]
    return "\n".join(rows)


def _message(subject_: str, text_: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = settings.mail_from
    msg["To"] = ", ".join(recipients())
    msg["Subject"] = subject_
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=settings.mail_from.rpartition("@")[2] or None)
    # So the daily alert is not filed as advertising and no out-of-office reply
    # comes back.
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(text_)
    return msg


def _via_smtp(subject_: str, text_: str) -> None:
    msg = _message(subject_, text_)
    host, port = settings.mail_smtp_host, settings.mail_smtp_port
    security = settings.mail_smtp_security
    context = ssl.create_default_context()

    if security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=settings.notify_timeout,
                                                context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=settings.notify_timeout)
    with server:
        if security == "starttls":
            server.starttls(context=context)
        if settings.mail_smtp_user:
            server.login(settings.mail_smtp_user, settings.mail_smtp_password)
        server.send_message(msg)


def _via_http(subject_: str, text_: str) -> None:
    provider = PROVIDERS[settings.mail_http_provider]
    url = provider["url"].format(domain=settings.mail_http_domain)
    body = provider["body"](settings.mail_from, recipients(), subject_, text_)

    kind, *rest = provider["auth"]
    headers = {"User-Agent": settings.ct_user_agent}
    auth = None
    if kind == "header":
        name, template = rest
        headers[name] = template.format(key=settings.mail_http_key)
    else:
        auth = (rest[0], settings.mail_http_key)

    with httpx.Client(timeout=settings.notify_timeout) as client:
        response = client.post(
            url, headers=headers, auth=auth,
            **({"data": body} if provider.get("form") else {"json": body}),
        )
    if response.status_code >= 400:
        # Pass the provider text along: a bare "401" does not say whether the key is
        # wrong or the sender address is not cleared.
        raise RuntimeError(f"{settings.mail_http_provider} answered "
                           f"{response.status_code}: {response.text[:200]}")


def send(subject_: str, text_: str) -> None:
    """Send a mail. Raises if it does not work, the caller keeps count."""
    ok, reason = configured()
    if not ok:
        raise RuntimeError(reason)
    (_via_smtp if settings.mail_transport == "smtp" else _via_http)(subject_, text_)


def status() -> dict[str, Any]:
    """The state for the system screen."""
    ok, reason = configured()
    route = settings.mail_transport
    if route == "http" and settings.mail_http_provider:
        route = f"http / {settings.mail_http_provider}"
    elif route == "smtp" and settings.mail_smtp_host:
        route = f"smtp / {settings.mail_smtp_host}:{settings.mail_smtp_port}"
    return {
        "state": reason,
        "ok": ok,
        "route": route,
        "recipients": recipients(),
    }
