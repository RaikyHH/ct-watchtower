"""Feed endpoints (§10.2): CSV, JSON, JSON Lines, domain list.

`?since=<ISO8601>` returns a delta. Every answer carries `ETag` and `Last-Modified`;
an `If-None-Match` is answered with `304` without reading any rows.

Deliberately simple: §10.2 provides for pre-generating the feeds every 5 minutes and
serving them from the file system, so many consumers cause no database load. At a
few hundred findings per tenant the query costs nothing, and the ETag answers repeats
without any work. Pre-generate as soon as a feed gets measurably expensive.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from email.utils import format_datetime

from flask import Blueprint, Response, current_app, jsonify, request

from ctwatchtower import export
from ctwatchtower.api.routes import _row, check_token
from ctwatchtower.config import settings

bp = Blueprint("feed", __name__, url_prefix="/feed")
bp.before_request(check_token)  # the same optional bearer token as the API (§10)

# Statuses that never belong in a feed (§11): deliberately an exclusion, not a
# selection. In doubt a new status should be included, not quietly missing.
EXCLUDED = ("false_positive", "suppressed")


def _ruleset(tenant: str):
    return next((rs for rs in current_app.config["RULES"].rulesets if rs.tenant.id == tenant), None)


def _rows(tenant: str, feed_from: float, since: str | None) -> list[dict]:
    sql = (
        "SELECT * FROM findings WHERE tenant_id=? AND score>=?"
        f" AND status NOT IN ({','.join('?' * len(EXCLUDED))})"
    )
    params: list = [tenant, feed_from, *EXCLUDED]
    if since:
        sql += " AND last_seen>=?"
        params.append(since)
    sql += " ORDER BY first_seen DESC"
    return [_row(r) for r in current_app.config["DB"].execute(sql, params)]


def _stamp(tenant: str, feed_from: float, since: str | None) -> tuple[str, str | None]:
    """A signature of the data: row count and latest change. Two cheap aggregates."""
    sql = (
        "SELECT COUNT(*) n, MAX(last_seen) newest FROM findings WHERE tenant_id=? AND score>=?"
        f" AND status NOT IN ({','.join('?' * len(EXCLUDED))})"
    )
    params: list = [tenant, feed_from, *EXCLUDED]
    if since:
        sql += " AND last_seen>=?"
        params.append(since)
    row = current_app.config["DB"].execute(sql, params).fetchone()
    return str(row["n"]), row["newest"]


def _respond(tenant: str, fmt: str) -> Response:
    rs = _ruleset(tenant)
    if rs is None:
        return jsonify({"error": f"there is no tenant '{tenant}'"}), 404
    if rs.shadow:
        # Trial mode (§15.2): findings yes, passing them on no. Serving an empty feed
        # would be worse than a clear refusal, the consumer would take "nothing
        # found" for a result.
        return jsonify(
            {
                "error": f"tenant '{tenant}' runs in trial mode (shadow) "
                "and serves no feed."
            }
        ), 409
    since = request.args.get("since") or None
    feed_from = rs.thresholds.feed_from

    count, newest = _stamp(tenant, feed_from, since)
    etag = '"{}"'.format(
        hashlib.sha256(
            f"{export.SCHEMA_VERSION}|{tenant}|{fmt}|{feed_from}|{since}|{count}|{newest}".encode()
        ).hexdigest()[:32]
    )
    if request.headers.get("If-None-Match") == etag:
        return Response(status=304, headers={"ETag": etag})

    rows = _rows(tenant, feed_from, since)
    ui = settings.ui_base_url
    if fmt == "csv":
        body, mime = export.to_csv(rows, ui_base=ui), "text/csv; charset=utf-8"
    elif fmt == "json":
        body = export.to_json(rows, tenant=tenant, tlp=rs.tenant.tlp, since=since,
                              ttl_days=settings.indicator_ttl_days, ui_base=ui)
        mime = "application/json"
    elif fmt == "jsonl":
        body = export.to_jsonl(rows, ttl_days=settings.indicator_ttl_days, ui_base=ui)
        mime = "application/x-ndjson"
    else:
        body, mime = export.to_domains(rows), "text/plain; charset=utf-8"

    headers = {"ETag": etag, "X-Feed-Count": str(len(rows))}
    if newest:
        try:
            when = datetime.fromisoformat(newest)
            headers["Last-Modified"] = format_datetime(
                when if when.tzinfo else when.replace(tzinfo=UTC), usegmt=True
            )
        except ValueError:
            pass
    return Response(body, mimetype=mime, headers=headers)


@bp.get("/<tenant>/indicators.csv")
def indicators_csv(tenant: str):
    return _respond(tenant, "csv")


@bp.get("/<tenant>/indicators.json")
def indicators_json(tenant: str):
    return _respond(tenant, "json")


@bp.get("/<tenant>/indicators.jsonl")
def indicators_jsonl(tenant: str):
    return _respond(tenant, "jsonl")


@bp.get("/<tenant>/domains.txt")
def domains_txt(tenant: str):
    return _respond(tenant, "domains")
