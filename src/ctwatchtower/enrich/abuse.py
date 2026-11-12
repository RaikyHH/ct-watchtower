"""Build an abuse report out of a finding (§17.2).

The text comes from `config/abuse_templates/<language>.txt` and can be edited
freely. Only the draft is produced. Nothing is sent: the UI opens the user's mail
program with it, and they read the text and can change it before sending.

That follows §16.3: a high score means "worth checking", not "malicious". A
complaint sent automatically would be exactly the verdict this system does not pass.
"""

from __future__ import annotations

import functools
import json
from typing import Any
from urllib.parse import quote

from ctwatchtower.config import REPO_ROOT

TEMPLATE_DIR = REPO_ROOT / "config" / "abuse_templates"
EMPTY = "-"
# Windows only opens `mailto:` reliably up to around 2000 characters. Above that the
# UI hands over the full report to copy instead of a truncated mail.
MAILTO_MAX = 1900


@functools.lru_cache(maxsize=8)
def template(language: str = "en") -> tuple[str, str]:
    """(subject, body) from the template file. Leading comment lines are dropped."""
    path = TEMPLATE_DIR / f"{language}.txt"
    if not path.is_file():
        path = TEMPLATE_DIR / "en.txt"
    rows = [r for r in path.read_text(encoding="utf-8").splitlines() if not r.startswith("#")]
    while rows and not rows[0].strip():
        rows.pop(0)
    subject = rows[0] if rows else "Abuse report: {domain}"
    return subject.strip(), "\n".join(rows[1:]).strip("\n")


def _as_text(value: Any) -> str:
    if isinstance(value, str) and value[:1] == "[":
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return value
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else EMPTY
    return EMPTY if value in (None, "") else str(value)


def fields(finding: dict[str, Any]) -> dict[str, str]:
    """Placeholder -> value. Anything unknown stays visibly empty, never invented."""
    explanation = finding.get("explanation") or {}
    matched = explanation.get("matched") if isinstance(explanation, dict) else None
    domain = finding.get("domain", "")
    return {
        "domain": domain,
        "registrable": _as_text(finding.get("registrable")),
        "tenant": _as_text(finding.get("tenant_id")),
        "score": _as_text(finding.get("score")),
        "severity": _as_text(finding.get("severity")),
        "matched": _as_text(list(matched) if matched else None),
        "first_seen": _as_text(finding.get("first_seen")),
        "issuer": _as_text(finding.get("issuer_o")),
        "cert_not_before": _as_text(finding.get("cert_not_before")),
        "cert_sha256": _as_text(finding.get("cert_sha256")),
        "ct_log": _as_text(finding.get("ct_log_id")),
        "ct_index": _as_text(finding.get("ct_log_index")),
        "registrar": _as_text(finding.get("registrar")),
        "domain_created": _as_text(finding.get("domain_created")),
        "nameservers": _as_text(finding.get("nameservers")),
        "a_records": _as_text(finding.get("a_records")),
        "epp_status": _as_text(finding.get("epp_status")),
        "crtsh_url": f"https://crt.sh/?q={quote(domain, safe='')}" if domain else EMPTY,
    }


def report(finding: dict[str, Any], language: str = "en") -> dict[str, Any]:
    """Recipient, subject, text and a `mailto:`, or the reason it will not work."""
    subject_template, body_template = template(language)
    values = fields(finding)

    def fill(text: str) -> str:
        for key, value in values.items():
            text = text.replace("{" + key + "}", value)
        return text

    subject, body = fill(subject_template), fill(body_template)
    recipient = finding.get("registrar_abuse_email") or ""
    # The `@` in the address part stays. Most mail programs swallow `%40`, but by
    # RFC 6068 it does not belong encoded there.
    mailto = (
        f"mailto:{quote(recipient, safe='@.')}"
        f"?subject={quote(subject, safe='')}&body={quote(body, safe='')}"
    )
    return {
        "to": recipient,
        "subject": subject,
        "body": body,
        "mailto": mailto,
        # Too long for Windows: then only copy, instead of opening a truncated mail.
        "mailto_ok": len(mailto) <= MAILTO_MAX,
        "reason": "" if recipient else "abuse address unknown, enrich the finding first",
    }
