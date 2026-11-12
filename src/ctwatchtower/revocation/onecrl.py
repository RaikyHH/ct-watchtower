"""Fetch Mozilla's OneCRL. The revocation list Firefox itself uses.

OneCRL sits publicly on Mozilla's Remote Settings infrastructure, the same one
millions of Firefox installations pull it from. One fetch a day is nothing against
that. Even so, we ask the way you are supposed to ask:

  * `If-None-Match` with the ETag we remembered. If nothing changed the server
    answers 304 and sends no payload.
  * No more often than `max-age` allows (the server says 3600 s).
  * With the product name as User-Agent, no contact details, as everywhere here.

Measured 2026-10-23: 1,907 records, 805 KB, of which 1,262 are active.

OneCRL names a revoked certificate in two ways, both are taken:

    issuerName + serialNumber   common (1,898 of 1,907)
    subject    + pubKeyHash     rare (9), that is how Mozilla revokes a
                                compromised key, eMudhra for instance
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import httpx

from ctwatchtower.config import settings
from ctwatchtower.revocation.der import readable

log = logging.getLogger(__name__)

URL = ("https://firefox.settings.services.mozilla.com/v1/buckets/security-state"
       "/collections/onecrl/records")

# The server says `max-age: 3600`. Asking more often gains nothing and is rude.
MIN_INTERVAL = 3600.0


class Unreachable(Exception):
    """The fetch went wrong. The list we already have stays in force."""


def fetch(etag: str | None = None, *, http: httpx.Client | None = None) -> tuple[list[dict], str | None]:
    """Fetch the list. Returns (entries, new ETag).

    On 304 it returns `([], etag)`. Nothing changed, and that is the normal case.
    So an empty list here does **not** mean "no revocations".
    """
    headers = {"User-Agent": settings.ct_user_agent, "Accept": "application/json"}
    if etag:
        headers["If-None-Match"] = etag

    own_client = http is None
    http = http or httpx.Client(timeout=30.0, follow_redirects=False)
    try:
        response = http.get(URL, headers=headers)
    except httpx.HTTPError as exc:
        raise Unreachable(f"OneCRL unreachable: {exc}") from exc
    finally:
        if own_client:
            http.close()

    if response.status_code == 304:
        log.info("OneCRL unchanged (304)")
        return [], etag
    if response.status_code != 200:
        raise Unreachable(f"OneCRL answered with HTTP {response.status_code}")

    try:
        data = response.json().get("data") or []
    except ValueError as exc:
        raise Unreachable("OneCRL did not return JSON") from exc
    if not isinstance(data, list) or not data:
        raise Unreachable("OneCRL returned an empty list: suspicious, not imported")

    return data, response.headers.get("ETag") or None


def _reason(record: dict[str, Any]) -> tuple[str, str]:
    """Reason and reference out of `details`, as far as the data goes."""
    d = record.get("details") or {}
    parts = [t for t in (d.get("name"), d.get("why")) if t]
    return ". ".join(parts) or "revoked by Mozilla (no reason in the record)", d.get("bug") or ""


def _name_from(b64: str) -> str:
    """Make the name of a base64-encoded DN readable."""
    try:
        return readable(base64.b64decode(b64))
    except (ValueError, TypeError):
        return ""


def entries(rulesets: list[dict]) -> list[dict[str, str]]:
    """Bring OneCRL records into our own shape.

    `enabled: false` is skipped: Mozilla keeps withdrawn revocations in the data
    set. A withdrawn revocation is not one.
    """
    out: list[dict[str, str]] = []
    for record in rulesets:
        if not record.get("enabled"):
            continue
        reason, reference = _reason(record)
        common = {"source": "onecrl", "reason": reason, "reference": reference,
                     "ident": str(record.get("id") or "")}
        if record.get("subject") and record.get("pubKeyHash"):
            # Without plain text the UI shows base64. The name sits in the subject;
            # for these entries Mozilla's `details` are usually empty.
            out.append({**common, "kind": "spki",
                        "name": _name_from(record["subject"]) or "key revocation",
                        "value": f"{record['subject']}|{record['pubKeyHash']}"})
        elif record.get("issuerName") and record.get("serialNumber"):
            out.append({**common, "kind": "issuer_serial",
                        "name": _name_from(record["issuerName"]) or "revocation",
                        "value": f"{record['issuerName']}|{record['serialNumber']}"})
    return out
