"""Trigger an analysis at an external scanner (§7.8, extension).

Unlike everything else in this package this is an **active** action: the service
visits the suspicious page. That has three consequences, and they shape the design:

1. It only ever happens at the push of a button for exactly one finding, never
   automatically, never in bulk. There is
   deliberately no function here that takes a list of domains.
2. Both services require in their terms that you are allowed to scan the URL. For a
   domain imitating your own brand that is the usual reading, and it stays a
   reading. So the switch is off by default.
3. A public scan is visible to the operator of the site. The default is therefore
   `private`; whoever wants `public` writes it down explicitly.

The result itself is neither fetched nor stored, we keep the result URL on the
finding. Only one thing is asked: **is it ready yet?** That is necessary because
urlscan only creates the result page once the scan is through; until then it
answers 404. Click the link right after triggering it and you land on an error page
and think the scan failed.

That question is free at the service: only answers with HTTP 200 count against the
quota there. The 404s during the wait do not.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from ctwatchtower.config import settings
from ctwatchtower.enrich.net import Defer, Quota, Transient, client

log = logging.getLogger(__name__)

VISIBILITIES = ("private", "unlisted", "public")


@dataclass(frozen=True)
class Service:
    name: str
    endpoint: str
    key_header: str
    visibility_field: str
    result_pattern: str
    # The address where you can ask whether the result is there yet. `None` means
    # the service offers nothing of the kind. The UI then shows the link right
    # away, the way it used to, instead of faking a readiness.
    status_pattern: str | None
    # Without a key nothing works at this service at all (urlscan), or only public
    # and unlisted scans do (scanmalware). `private` needs a key there as well.
    key_required: bool

    def key(self) -> str | None:
        return getattr(settings, f"{self.name}_api_key", None) or None


SERVICES: dict[str, Service] = {
    "urlscan": Service(
        name="urlscan",
        endpoint="https://urlscan.io/api/v1/scan/",
        key_header="API-Key",
        visibility_field="visibility",
        result_pattern="https://urlscan.io/result/{id}/",
        status_pattern="https://urlscan.io/api/v1/result/{id}/",
        key_required=True,
    ),
    "scanmalware": Service(
        name="scanmalware",
        endpoint="https://scanmalware.com/api/v1/scan",
        key_header="X-API-Key",
        visibility_field="scan_type",
        result_pattern="https://scanmalware.com/result/{id}",
        # No documented way to ask whether it has finished.
        status_pattern=None,
        key_required=False,
    ),
}


class ScanError(Exception):
    """The service refused the submission. Not a network problem, no retry."""


def _id_from(response: dict[str, Any]) -> str | None:
    # urlscan answers with `uuid`, scanmalware with `scan_id`.
    for field in ("uuid", "scan_id", "id"):
        if value := response.get(field):
            return str(value)
    return None


def submit(
    domain: str,
    service_name: str,
    *,
    quota: Quota | None = None,
    visibility: str | None = None,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """Submit exactly one domain to exactly one service.

    Returns `{"service", "scan_id", "result", "visibility", "submitted_at"}`.
    Raises `ScanError` (final), `Transient` (try later) or `Defer` (cap reached).
    """
    service = SERVICES.get(service_name)
    if service is None:
        raise ScanError(f"unknown service {service_name!r}")
    if not settings.scan_enabled:
        raise ScanError("scan submission is switched off (SCAN_ENABLED)")

    visibility = visibility or settings.scan_visibility
    if visibility not in VISIBILITIES:
        raise ScanError(f"visibility {visibility!r} is not one of {VISIBILITIES}")

    key = service.key()
    if not key and (service.key_required or visibility == "private"):
        raise ScanError(
            f"{service.name}: `{visibility}` needs an API key "
            f"({service.name.upper()}_API_KEY in the .env)"
        )

    # The daily cap counts per service, so an outage at one does not eat the
    # other's budget. It applies before the network call, not after.
    if quota is not None:
        quota.take({f"scan:{service.name}": settings.scan_daily})

    # Deliberately `https://` and the bare name: no paths, no parameters, nothing
    # that came out of the certificate. The service fetches the rest itself.
    url = f"https://{domain}"
    headers = {service.key_header: key} if key else {}
    payload = {"url": url, service.visibility_field: visibility}

    own_client = http is None
    http = http or client("application/json")
    try:
        response = http.post(service.endpoint, json=payload, headers=headers)
    except httpx.HTTPError as exc:
        raise Transient(f"{service.name}: {exc}") from exc
    finally:
        if own_client:
            http.close()

    if response.status_code == 429:
        raise Defer(60.0, f"{service.name} is throttling")
    if response.status_code >= 500:
        raise Transient(f"{service.name}: HTTP {response.status_code}")
    if response.status_code >= 400:
        raise ScanError(f"{service.name}: HTTP {response.status_code}, {response.text[:200]}")

    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        raise Transient(f"{service.name}: no JSON answer") from exc

    scan_id = _id_from(data)
    if not scan_id:
        raise ScanError(f"{service.name}: answer without a scan id")

    # Both send `result` along themselves; the pattern is only the fallback.
    result = str(data.get("result") or service.result_pattern.format(id=scan_id))
    if not result.startswith("https://"):
        result = service.result_pattern.format(id=scan_id)

    log.info("analysis submitted: %s at %s (%s)", domain, service.name, visibility)
    return {
        "service": service.name,
        "scan_id": scan_id,
        "result": result,
        "visibility": visibility,
        "submitted_at": str(data.get("submitted_at") or ""),
    }


# More attempts than this and something is wrong. urlscan is usually done after
# ten to thirty seconds; whoever still gets a 404 after this many queries will
# probably get one forever, because the scan got stuck at the service, say. Then
# the asking stops instead of keeping somebody else's service busy forever if a
# browser window is left open.
MAX_POLLS = 40


def is_ready(
    service_name: str,
    scan_id: str,
    *,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """Can the result be fetched? Exactly **one** query, no loop, no waiting.

    The loop belongs in the UI, not here: a server waiting on somebody else's
    service keeps a worker busy and says nothing to the user in the meantime.

    States: `running` (not finished yet), `done`, `deleted` (the service removed
    the result, which it may do at any time), `throttled` (with `retry_after`),
    `unknown` (the service has no such endpoint) and `error`.
    """
    service = SERVICES.get(service_name)
    if service is None or not service.status_pattern:
        return {"state": "unknown"}

    headers = {service.key_header: key} if (key := service.key()) else {}
    own_client = http is None
    http = http or client("application/json")
    try:
        response = http.get(service.status_pattern.format(id=scan_id), headers=headers)
    except httpx.HTTPError as exc:
        # A network blip is no verdict about the scan, keep asking.
        return {"state": "running", "note": str(exc)[:120]}
    finally:
        if own_client:
            http.close()

    if response.status_code == 200:
        return {"state": "done"}
    # A 404 is no fault here, it is the documented answer "still running".
    if response.status_code == 404:
        return {"state": "running"}
    if response.status_code == 410:
        return {"state": "deleted"}
    if response.status_code == 429:
        header = response.headers.get("X-Rate-Limit-Reset-After")
        try:
            wait = float(header) if header else 60.0
        except ValueError:
            wait = 60.0
        return {"state": "throttled", "retry_after": min(max(wait, 5.0), 300.0)}
    if response.status_code >= 500:
        return {"state": "running", "note": f"HTTP {response.status_code}"}
    return {"state": "error", "note": f"HTTP {response.status_code}"}
