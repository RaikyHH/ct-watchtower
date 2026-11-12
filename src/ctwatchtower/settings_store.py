"""Settings through the UI instead of through the file.

**The problem being solved here.** Everything except the rules sat in `.env` and only
took effect after a container restart. Whoever wanted to switch enrichment on had to
go to the deployment. For an application that is otherwise operated through forms,
that is the wrong way round.

**Where a value comes from.** Three layers, the upper one wins:

1. the default in the code (`config.py`)
2. `.env` or the environment
3. the `settings` table: whatever somebody changed here

Only layer 3 is stored, and only what was actually changed. That way it stays
readable what was deliberately moved, and "reset" means: delete the row, not type the
default back in. The UI shows per value which layer it came from.

**Takes effect without a restart.** `settings` is one single object every other part
reads at runtime. A `setattr` on it therefore works at once, provided the reading
side asks on every call and not once at startup. That is exactly why the enricher is
always built, even when it is off.

**What does not belong here.** Everything to do with the deployment: database path,
CertStream address, queue size, the API token, the log level. That does not change
during operation, and a field for it in the UI would be an invitation to lock
yourself out.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime
from typing import Any, Literal, NamedTuple

from ctwatchtower.config import settings

log = logging.getLogger(__name__)


class Field(NamedTuple):
    """One adjustable value: what it is called, what it means, what is allowed."""

    name: str
    label: str
    kind: Literal["bool", "int", "float", "text", "choice", "secret"]
    help: str = ""
    choice: tuple[str, ...] = ()
    min: float | None = None
    max: float | None = None
    unit: str = ""


# Groups in the order they appear on the screen. The texts are the same ones that are
# in `.env.example`. Two explanations of the same thing drift apart.
GROUPS: list[tuple[str, str, list[Field]]] = [
    (
        "enrichment",
        "Enrichment",
        [
            Field("enrich_enabled", "Enrichment switched on", "bool",
                  "Fetches registrar, domain age and DNS records."),
            Field("enrich_auto", "Enrich by itself", "bool",
                  "Without a click, from the tenant's threshold upwards (Rules, step 2). "
                  "The precondition for campaigns."),
            Field("enrich_rdap_enabled", "Use RDAP", "bool",
                  "The registration data. Without RDAP, registrar and domain age stay empty."),
            Field("enrich_whois_fallback", "WHOIS as a fallback", "bool",
                  "For endings without RDAP (.cn, .eu, .io). WHOIS has the strictest terms "
                  "of use."),
            Field("enrich_doh_enabled", "DNS over DoH", "bool",
                  "Nameservers, A records, MX. Through a public resolver, never the domain "
                  "itself."),
            Field("enrich_rdap_daily", "RDAP per day", "int",
                  "A hard cap, counted in the database, survives a restart.",
                  min=0, max=5000, unit="queries"),
            Field("enrich_rdap_daily_per_server", "RDAP per day and server", "int",
                  "On top of the overall cap: no single registry server should carry the "
                  "load alone.", min=0, max=2000, unit="queries"),
            Field("enrich_whois_daily", "WHOIS per day", "int", min=0, max=1000,
                  unit="queries"),
            Field("enrich_doh_daily", "DNS per day", "int", min=0, max=50_000,
                  unit="queries"),
        ],
    ),
    (
        "analysis",
        "Trigger an analysis",
        [
            Field("scan_enabled", "Allow triggering an analysis", "bool",
                  "The service visits the suspicious page, not this application."),
            Field("scan_visibility", "Visibility", "choice",
                  "`public` is visible to the operator of the site.",
                  choice=("private", "unlisted", "public")),
            Field("scan_daily", "Triggers per day and service", "int", min=0, max=500),
            Field("urlscan_api_key", "urlscan.io: key", "secret",
                  "Mandatory at urlscan, even for public scans."),
            Field("scanmalware_api_key", "scanmalware.com: key", "secret",
                  "Only needed for private scans."),
        ],
    ),
    (
        "alerting",
        "Alerting",
        [
            Field("notify_enabled", "Alerting switched on", "bool",
                  "The main switch for webhook and mail."),
            Field("notify_min_severity", "From which severity", "choice",
                  choice=("info", "warning", "alert")),
            Field("notify_window", "Collection window", "int",
                  "Findings collected in it go out as one message.",
                  min=30, max=3600, unit="seconds"),
            Field("notify_max_per_hour", "At most per hour", "int",
                  "Above that nothing more is sent.",
                  min=1, max=120, unit="messages"),
            Field("notify_renotify_days", "The same domain again only after", "int",
                  "Unless the score rises sharply.", min=0, max=365, unit="days"),
            Field("notify_webhook_url", "Webhook address", "text",
                  "Leave empty if only mail should go out."),
            Field("notify_secret", "Webhook secret", "secret",
                  "Set -> HMAC-SHA256 over the body in the X-Watchtower-Signature header."),
        ],
    ),
    (
        "mail",
        "Mail",
        [
            Field("mail_enabled", "Mail switched on", "bool"),
            Field("mail_from", "Sender", "text"),
            Field("mail_to", "Recipients", "text", "Several separated by commas."),
            Field("mail_transport", "Route", "choice",
                  "`smtp` needs open ports (25, 465, 587). `http` uses the same provider "
                  "through its HTTPS interface, on port 443.",
                  choice=("smtp", "http")),
            Field("mail_smtp_host", "SMTP server", "text"),
            Field("mail_smtp_port", "SMTP port", "int", min=1, max=65535),
            Field("mail_smtp_security", "Encryption", "choice",
                  choice=("starttls", "ssl", "none")),
            Field("mail_smtp_user", "SMTP user", "text",
                  "Leave empty if the relay accepts without a login."),
            Field("mail_smtp_password", "SMTP password", "secret"),
            Field("mail_http_provider", "Provider", "choice",
                  choice=("", "brevo", "mailgun", "mailgun_eu", "postmark", "resend",
                          "sendgrid")),
            Field("mail_http_key", "The provider's key", "secret"),
            Field("mail_http_domain", "Sender domain", "text",
                  "Mailgun only: the domain registered there."),
        ],
    ),
    (
        "operation",
        "Operation",
        [
            Field("retention_days", "Keep findings for", "int",
                  "After that they are deleted. Confirmed and reported ones stay.",
                  min=1, max=3650, unit="days"),
            Field("ui_base_url", "Address of this UI", "text",
                  "For the links in feeds and alerts, e.g. https://watchtower.internal. "
                  "Empty means no links."),
            Field("abuse_language", "Language of the abuse template", "choice",
                  choice=("en", "de")),
            Field("indicator_ttl_days", "Validity in the feed", "int",
                  "`valid_until` per indicator.", min=1, max=3650, unit="days"),
        ],
    ),
    (
        "revocation",
        "Revoked CA certificates",
        [
            Field("revocation_enabled", "Sync the revocation list", "bool",
                  "Fetches Mozilla's OneCRL. The same list Firefox uses."),
            Field("revocation_interval_hours", "Interval", "int",
                  "The server allows hourly at the earliest. Unchanged means 304, so no "
                  "payload.", min=1, max=168, unit="hours"),
        ],
    ),
]

FIELDS: dict[str, Field] = {f.name: f for _, _, fields in GROUPS for f in fields}


def _coerce(field: Field, raw: Any) -> Any:
    """Text from the database or the form into the type of the setting."""
    if field.kind == "bool":
        return raw if isinstance(raw, bool) else str(raw).lower() in ("1", "true", "on", "yes")
    if field.kind == "int":
        return int(float(raw))
    if field.kind == "float":
        return float(raw)
    value = str(raw)
    if field.kind == "choice" and field.choice and value not in field.choice:
        raise ValueError(f"'{value}' is not allowed. Possible: {', '.join(field.choice)}")
    return value


def validate(name: str, raw: Any) -> Any:
    """Accept a value, or refuse it with a reason."""
    field = FIELDS.get(name)
    if field is None:
        raise KeyError(f"'{name}' is not a setting that can be changed here")
    try:
        value = _coerce(field, raw)
    except ValueError as exc:
        raise ValueError(f"{field.label}: {exc}") from exc
    if field.min is not None and value < field.min:
        raise ValueError(f"{field.label}: smaller than {field.min:g} does not work")
    if field.max is not None and value > field.max:
        raise ValueError(f"{field.label}: larger than {field.max:g} does not work")
    return value


def stored(conn: sqlite3.Connection) -> dict[str, Any]:
    """What is in the database, already in the right type."""
    out: dict[str, Any] = {}
    for row in conn.execute("SELECT key, value FROM settings"):
        field = FIELDS.get(row["key"])
        if field is None:
            continue  # left over from an older version: harmless, does not apply
        try:
            out[row["key"]] = _coerce(field, row["value"])
        except ValueError:
            log.warning("setting %s in the database is unusable, skipped", row["key"])
    return out


def apply_stored(conn: sqlite3.Connection) -> int:
    """Put the stored values onto `settings`. Returns how many there were.

    Called at startup and after every change. Because every part reads the same
    `settings` object at runtime, it takes effect at once.
    """
    values = stored(conn)
    for name, value in values.items():
        setattr(settings, name, value)
    return len(values)


def put(conn: sqlite3.Connection, name: str, raw: Any) -> Any:
    """Change one setting. Raises on an unknown name or an inadmissible value."""
    value = validate(name, raw)
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?,?,?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (name, str(value), datetime.now(UTC).isoformat()),
    )
    conn.commit()
    setattr(settings, name, value)
    return value


def reset(conn: sqlite3.Connection, name: str) -> None:
    """Throw the stored value away. From then on `.env` or the default applies again.

    For that the starting value has to be known: `DEFAULTS` holds it as it came out
    of environment and defaults at startup.
    """
    if name not in FIELDS:
        raise KeyError(f"'{name}' is not a setting that can be changed here")
    conn.execute("DELETE FROM settings WHERE key=?", (name,))
    conn.commit()
    setattr(settings, name, DEFAULTS[name])


def for_form(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """The groups for the form, each field with its value and its origin."""
    here = stored(conn)
    groups = []
    for ident, title, fields in GROUPS:
        entries = []
        for f in fields:
            value = getattr(settings, f.name)
            entries.append({
                "name": f.name,
                "label": f.label,
                "kind": f.kind,
                "help": f.help,
                "choice": list(f.choice),
                "min": f.min,
                "max": f.max,
                "unit": f.unit,
                # Secrets never go back to the browser: whoever may read them may also
                # set them again.
                "value": ("" if f.kind == "secret" else value),
                "is_set": bool(value) if f.kind == "secret" else None,
                "changed_here": f.name in here,
                "default": ("" if f.kind == "secret" else DEFAULTS[f.name]),
            })
        groups.append({"ident": ident, "title": title, "fields": entries})
    return groups


# The state as it came out of the defaults and `.env`, before anything the database
# overwrites later. Captured at import time, before `apply_stored` runs for the first
# time.
DEFAULTS: dict[str, Any] = {name: getattr(settings, name) for name in FIELDS}
