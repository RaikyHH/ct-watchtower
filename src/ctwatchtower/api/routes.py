"""REST and SSE routes under `/api/v1` (§10.1, addendum §1, §4, §5).

Principles that are not negotiable here:

* `/lookup` and the rule test field call `scoring.engine.score_candidate`; there is
  no second scoring logic (addendum §2).
* A rule write validates through `rules.schema.RuleSet` and puts the canonical YAML
  file back with a `ruamel.yaml` round trip; the file stays the source of truth
  (addendum §1).
* Sorting and pagination happen in SQL, not in the client (addendum §4).
"""

from __future__ import annotations

import base64
import io
import json
import os
import queue
import re
import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, request
from ruamel.yaml import YAML

from ctwatchtower import settings_store
from ctwatchtower.config import settings
from ctwatchtower.db import audit_log, sync_tenants
from ctwatchtower.enrich.scan import SERVICES
from ctwatchtower.normalize.names import normalize
from ctwatchtower.pseudo_tenants import PSEUDO
from ctwatchtower.rules.loader import RuleLoadError, load_ruleset, ruleset_files
from ctwatchtower.rules.prose import explain_ruleset
from ctwatchtower.rules.schema import RuleSet, drop_source
from ctwatchtower.scoring.engine import score_candidate

bp = Blueprint("api", __name__, url_prefix="/api/v1")

# kebab-case, which rules out `..` and `/`. The length is capped because the id
# becomes a file name. File systems give up at 255 characters, and a 200-character
# tenant id is not one anyway, it is an accident.
TENANT_ID = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
TENANT_ID_MAX = 64
STATUSES = ("new", "confirmed", "false_positive", "suppressed", "reported")
SORTABLE = {"first_seen", "last_seen", "score"}
CAMPAIGN_SORTS = {"newest": "c.first_seen", "largest": "size", "score": "max_score"}
JSON_COLUMNS = ("explanation", "related_names", "nameservers", "a_records", "epp_status", "scans")

def _rt_yaml() -> YAML:
    """Round-trip parser: comments and order are preserved.

    One instance per call. Ruamel keeps read and write state in the object, and two
    concurrent requests stepped on each other's buffer in there.
    """
    y = YAML()
    y.preserve_quotes = True
    return y


# ------------------------------- Helpers -------------------------------


def _err(status: int, message: str, **extra: Any):
    return jsonify({"error": message, **extra}), status


def _db():
    return current_app.config["DB"]


def _store():
    return current_app.config["RULES"]


def _pipeline():
    return current_app.config["PIPELINE"]


def _rules_dir() -> Path:
    return Path(current_app.config["RULES_DIR"])


def _tenant_path(tenant_id: str) -> Path:
    return _rules_dir() / f"{tenant_id}.yaml"


def _int_arg(name: str, default: int | None = None) -> int | None:
    raw = request.args.get(name)
    if raw in (None, ""):
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} has to be a whole number") from exc


def check_token() -> Response | None:
    """An optional static bearer token (§1.2, §10). Without `API_TOKEN` it is open."""
    token = current_app.config.get("API_TOKEN")
    if not token or request.method == "OPTIONS":
        return None
    header = request.headers.get("Authorization", "")
    if header == f"Bearer {token}":
        return None
    return _err(401, "bearer token missing or wrong")


bp.before_request(check_token)


# ------------------------- Writing rule files -------------------------


def _deep_merge(base: dict, patch: dict) -> dict:
    """The PATCH semantics of the rule form: scalars overwrite, lists replace.

    Deliberately different from the `includes` merge in the loader: whoever removes
    a chip in the form wants it gone, not appended.

    Comments: the block **above** the key stays, it explains what the section is for
    and still holds. Whatever hung off the replaced value itself goes; that is no
    cosmetic decision but necessary: ruamel otherwise carries such a comment on to
    the next place and writes nonsense (`combos: -`) that cannot be read back in.
    """
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            if key in base and hasattr(base, "ca"):
                old = base.ca.items.pop(key, None)
                # Slot 1 is the comment block before the key; 0, 2 and 3 hang off
                # the value that is about to disappear.
                if old and old[1]:
                    base.ca.items[key] = [None, old[1], None, None]
            base[key] = value
    return base


def _dump(doc: Any) -> str:
    """The only way a rule document turns into YAML: check tmp, file, preview.

    `source` is a read field from `GET .../rules`; a form that sends it back must
    never get it into the file. Hence here and not per route.
    """
    drop_source(doc)
    buf = io.StringIO()
    _rt_yaml().dump(doc, buf)
    return buf.getvalue()


def _validate_doc(doc: Any, path: Path) -> RuleSet:
    """Validates including `includes`. For that the document has to sit in the rules dir.

    The temporary file starts with a dot and ends in `.tmp`; the loader sees it
    neither as a tenant nor as an include. The random part in the name is not
    decoration: two concurrent checks of the same tenant otherwise landed on the
    same file, and one read what the other was deleting.
    """
    tmp = path.parent / f".{path.name}.{uuid.uuid4().hex[:8]}.tmp"
    tmp.write_text(_dump(doc), encoding="utf-8")
    try:
        rs = load_ruleset(tmp, root=path.parent)
    finally:
        tmp.unlink(missing_ok=True)
    # The groups would otherwise carry the name of the temporary file. That does not
    # only leak a file name outwards, it also makes "own" indistinguishable from
    # "inherited", and the explanation then folded the own rules away with them.
    for group in (*rs.anchors, *rs.lures, *rs.tlds.groups):
        if group.source == tmp.name:
            group.source = path.name
    return rs


def _write_validated(path: Path, doc: Any) -> RuleSet:
    """Check, write next to it, then rename.

    Writing straight into the target file needs rights **on the file**. On the volume
    a rule file belonged to a different user and every save failed. Renaming only
    needs rights **on the directory**, and it is atomic: an aborted write leaves no
    half a rule file behind for the pipeline to choke on.
    """
    ruleset = _validate_doc(doc, path)  # check first, then write
    fresh = path.parent / f".{path.name}.{uuid.uuid4().hex[:8]}.new"
    try:
        fresh.write_text(_dump(doc), encoding="utf-8")
        os.replace(fresh, path)
    except OSError as exc:
        fresh.unlink(missing_ok=True)
        # Now it is the directory, not the file any more. As a bare 500 the user
        # looked for the mistake in their rules instead of in the permissions.
        raise RuleLoadError(
            f"{path.name} cannot be saved ({exc.strerror}). "
            "The rules directory is not writable; in the container the volume "
            "`rules` belongs to user 10001."
        ) from exc
    return ruleset


def _rules_payload(ruleset: RuleSet) -> dict:
    return ruleset.model_dump(by_alias=True, exclude_none=True)


# ──────────────────────────── status ────────────────────────────


@bp.get("/status")
def status():
    pipeline = _pipeline()
    row = _db().execute("SELECT COUNT(*) AS n FROM findings").fetchone()
    return jsonify(
        {
            "tenants": len(_store().rulesets),
            "findings": row["n"],
            "queue_depth": pipeline.queue.qsize(),
            "queue_depth_pct": pipeline.queue_depth_pct,
            "certs_per_sec": pipeline.certs_per_sec,
            "ingest_connected": pipeline.ingest.alive,
            "certstream_url": pipeline.ingest.url,
        }
    )


# ──────────────────────────── tenants ───────────────────────────


@bp.get("/tenants")
def list_tenants():
    counts = {
        r["tenant_id"]: dict(r)
        for r in _db().execute(
            "SELECT tenant_id, COUNT(*) AS findings,"
            " SUM(severity='alert') AS alerts, MAX(last_seen) AS last_seen"
            " FROM findings GROUP BY tenant_id"
        )
    }
    out = []
    for rs in _store().all_rulesets:  # `enabled` says which ones the pipeline scores
        stats = counts.get(rs.tenant.id, {})
        out.append(
            {
                "id": rs.tenant.id,
                "name": rs.tenant.name,
                "enabled": rs.tenant.enabled,
                "tlp": rs.tenant.tlp,
                "ruleset_hash": rs.ruleset_hash,
                "anchors": len(rs.anchor_terms),
                "findings": stats.get("findings", 0),
                "alerts": stats.get("alerts") or 0,
                "last_seen": stats.get("last_seen"),
            }
        )
    return jsonify({"items": out})


@bp.post("/tenants")
def create_tenant():
    body = request.get_json(silent=True) or {}
    # Do not lower-case it, refuse it: on Windows the file system is case-insensitive,
    # so "Velton" would otherwise hit "velton".
    tenant_id = str(body.get("id", "")).strip()
    if not TENANT_ID.match(tenant_id) or len(tenant_id) > TENANT_ID_MAX:
        return _err(400, "the id has to be kebab-case (a-z, 0-9, hyphen)")
    # The schema refuses these ids anyway, but here with a sentence that explains
    # why, instead of a validation error from the depths.
    if tenant_id in PSEUDO:
        return _err(409, f"{PSEUDO[tenant_id]} is a fixed view in the tenant "
                         f"picker, that id is taken.")
    path = _tenant_path(tenant_id)
    if path.exists() or any(p.stem == tenant_id for p in ruleset_files(_rules_dir())):
        return _err(409, f"tenant '{tenant_id}' already exists")

    template = _rules_dir() / "_template.yaml"
    if not template.is_file():
        return _err(500, "rules/_template.yaml is missing")
    doc = _rt_yaml().load(template.read_text(encoding="utf-8"))
    doc["tenant"]["id"] = tenant_id
    doc["tenant"]["name"] = str(body.get("name") or tenant_id)
    if body.get("description"):
        doc["tenant"]["description"] = str(body["description"])

    try:
        ruleset = _write_validated(path, doc)
    except RuleLoadError as exc:
        return _err(422, str(exc))
    sync_tenants(_db(), [ruleset])  # foreign key from findings/campaigns
    return jsonify({"id": ruleset.tenant.id, "rules": _rules_payload(ruleset)}), 201


@bp.delete("/tenants/<tenant_id>")
def delete_tenant(tenant_id: str):
    if not TENANT_ID.match(tenant_id) or len(tenant_id) > TENANT_ID_MAX:
        return _err(400, "invalid tenant id")
    path = _tenant_path(tenant_id)
    if not path.is_file():
        return _err(404, f"tenant '{tenant_id}' not found")
    conn = _db()
    # Findings hang off the tenant via ON DELETE CASCADE. Never delete them silently.
    n = conn.execute("SELECT COUNT(*) FROM findings WHERE tenant_id=?", (tenant_id,)).fetchone()[0]
    # A flag gets typed by accident; the tenant's name does not.
    if n and request.args.get("confirm") != tenant_id:
        return _err(
            409,
            f"tenant '{tenant_id}' has {n} findings; to delete them too append "
            f"?confirm={tenant_id}",
            findings=n,
        )
    # The trace first, then the action: if the delete fails, at least it says that
    # it was attempted.
    audit_log(
        conn, "tenant.delete", tenant_id,
        detail=f"{n} findings deleted too" if n else "no findings",
        source=f"{request.remote_addr or '?'} {(request.user_agent.string or '?')[:120]}",
    )
    path.unlink()
    conn.execute("DELETE FROM tenants WHERE id=?", (tenant_id,))
    conn.commit()
    return "", 204


# ───────────────────────── tenants/{id}/rules ────────────────────


def _load_for_edit(tenant_id: str):
    """(path, raw document) or an error response."""
    if not TENANT_ID.match(tenant_id) or len(tenant_id) > TENANT_ID_MAX:
        return None, None, _err(400, "invalid tenant id")
    path = _tenant_path(tenant_id)
    if not path.is_file():
        return None, None, _err(404, f"tenant '{tenant_id}' not found")
    return path, _rt_yaml().load(path.read_text(encoding="utf-8")), None


@bp.get("/tenants/<tenant_id>/rules")
def get_rules(tenant_id: str):
    ruleset = _store().get(tenant_id)
    if ruleset is None:
        return _err(404, f"tenant '{tenant_id}' not found")
    return jsonify(_rules_payload(ruleset))


@bp.route("/tenants/<tenant_id>/rules", methods=["PUT", "PATCH"])
def write_rules(tenant_id: str):
    path, doc, error = _load_for_edit(tenant_id)
    if error:
        return error
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _err(400, "a JSON object was expected")

    if request.method == "PUT":
        includes = doc.get("includes")
        doc = dict(body)
        doc.setdefault("includes", includes or [])
    else:
        _deep_merge(doc, body)
    doc.setdefault("tenant", {})["id"] = tenant_id  # the id stays tied to the file name

    try:
        ruleset = _write_validated(path, doc)
    except RuleLoadError as exc:
        return _err(422, str(exc))
    sync_tenants(_db(), [ruleset])
    return jsonify({"rules": _rules_payload(ruleset), "yaml": path.read_text(encoding="utf-8")})


@bp.post("/tenants/<tenant_id>/rules/validate")
def validate_rules(tenant_id: str):
    path, doc, error = _load_for_edit(tenant_id)
    if error:
        return error
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _err(400, "a JSON object was expected")
    _deep_merge(doc, body)
    try:
        ruleset = _validate_doc(doc, path)
    except RuleLoadError as exc:
        return jsonify({"valid": False, "error": str(exc)})
    return jsonify(
        {
            "valid": True,
            "rules": _rules_payload(ruleset),
            "yaml": _dump(doc),
            # The explanation comes from the validated model, not from the form: it is
            # meant to show what the engine will do, not what somebody typed.
            # With the inherited groups, otherwise it claims "no rule yet" while rules
            # from `includes` have been firing all along.
            "prose": [asdict(a) for a in explain_ruleset(ruleset, with_inherited=True)],
        }
    )


# ──────────────────────────── findings ──────────────────────────


def _row(row) -> dict:
    out = dict(row)
    for key in JSON_COLUMNS:
        value = out.get(key)
        if isinstance(value, str) and value[:1] in ("[", "{"):
            try:
                out[key] = json.loads(value)
            except json.JSONDecodeError:
                pass
    for key in ("is_idn", "is_wildcard", "has_mx"):
        if out.get(key) is not None:
            out[key] = bool(out[key])
    return out


def _encode_cursor(row, column: str) -> str:
    return base64.urlsafe_b64encode(f"{row[column]}\x1f{row['id']}".encode()).decode()


def _decode_cursor(raw: str) -> tuple[str, str]:
    value, _, fid = base64.urlsafe_b64decode(raw.encode()).decode().partition("\x1f")
    return value, fid


@bp.get("/findings")
def list_findings():
    sort = request.args.get("sort", "first_seen")
    if sort not in SORTABLE:
        return _err(400, f"sort has to be one of {sorted(SORTABLE)}")
    try:
        limit = max(1, min(_int_arg("limit", 50), 500))
        min_score, max_score = _int_arg("min_score"), _int_arg("max_score")
    except ValueError as exc:
        return _err(400, str(exc))

    where, params = [], []
    simple = {
        "tenant": "tenant_id",
        "severity": "severity",
        "status": "status",
        "tld": "tld",
        "registrar": "registrar",
        "country": "country",
        "campaign": "campaign_id",
    }
    for arg, column in simple.items():
        value = request.args.get(arg)
        if value:
            where.append(f"{column} = ?")
            params.append(value)
    if asn := request.args.get("asn"):
        try:
            params.append(int(asn))
        except ValueError:
            return _err(400, "asn has to be a whole number")
        where.append("asn = ?")
    if min_score is not None:
        where.append("score >= ?")
        params.append(min_score)
    if max_score is not None:
        where.append("score <= ?")
        params.append(max_score)
    if since := request.args.get("since"):
        where.append("first_seen >= ?")
        params.append(since)
    if until := request.args.get("until"):
        where.append("first_seen <= ?")
        params.append(until)
    if q := request.args.get("q"):
        where.append("domain LIKE ?")
        params.append(f"%{q}%")

    if cursor := request.args.get("cursor"):
        try:
            value, fid = _decode_cursor(cursor)
        except (ValueError, UnicodeDecodeError):
            return _err(400, "the cursor is unreadable")
        where.append(f"({sort} < ? OR ({sort} = ? AND id < ?))")
        params += [value, value, fid]

    sql = "SELECT * FROM findings"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {sort} DESC, id DESC LIMIT ?"
    rows = _db().execute(sql, (*params, limit + 1)).fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]
    return jsonify(
        {
            "items": [_row(r) for r in rows],
            "next_cursor": _encode_cursor(rows[-1], sort) if has_more and rows else None,
            "sort": sort,
            "limit": limit,
        }
    )


@bp.get("/findings/<finding_id>")
def get_finding(finding_id: str):
    row = _db().execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if row is None:
        return _err(404, "finding not found")
    return jsonify(_row(row))


@bp.patch("/findings/<finding_id>")
def patch_finding(finding_id: str):
    body = request.get_json(silent=True) or {}
    fields, params = [], []
    if "status" in body:
        if body["status"] not in STATUSES:
            return _err(400, f"status has to be one of {list(STATUSES)}")
        fields += ["status = ?", "status_at = datetime('now')"]
        params.append(body["status"])
    if "note" in body:
        fields.append("status_note = ?")
        params.append(body["note"])
    if not fields:
        return _err(400, "neither status nor note was given")

    conn = _db()
    cur = conn.execute(
        f"UPDATE findings SET {', '.join(fields)} WHERE id=?", (*params, finding_id)
    )
    conn.commit()
    if cur.rowcount == 0:
        return _err(404, "finding not found")
    return jsonify(_row(conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()))


@bp.post("/findings/<finding_id>/enrich")
def enrich_finding(finding_id: str):
    """Request enrichment for **one** finding. The only way to RDAP/WHOIS/DoH.

    The operators allow single queries, not automated bulk ones (§16), so there is no
    batch mode and no automatic mode.
    """
    status = _pipeline().request_enrichment(finding_id)
    if status == "unknown":
        # `_err` has a parameter called `status` itself, so build it directly here.
        return jsonify({"error": "finding not found", "status": "unknown"}), 404
    row = _db().execute("SELECT enrich_state FROM findings WHERE id=?", (finding_id,)).fetchone()
    body = {"status": status, "enrich_state": row["enrich_state"] if row else None}
    if status == "quota":
        body["quota"] = _pipeline().metrics()["enrich_quota"]
    return jsonify(body), 202 if status == "queued" else 200


@bp.post("/findings/<finding_id>/scan")
def scan_finding(finding_id: str):
    """Trigger an analysis at an external scanner, for **one** finding.

    The only action where the suspicious page gets visited; the service does it, not
    us. Both services require that you are allowed to scan the URL, hence an explicit
    button per finding and no batch mode.
    """
    service = (request.get_json(silent=True) or {}).get("service", "")
    if service not in SERVICES:
        return _err(400, f"service has to be one of {sorted(SERVICES)}")
    result = _pipeline().request_scan(finding_id, service)
    if result["status"] == "unknown":
        return jsonify({"error": "finding not found", "status": "unknown"}), 404
    code = {"done": 200, "disabled": 409, "quota": 429, "error": 502}[result["status"]]
    return jsonify(result), code


@bp.get("/findings/<finding_id>/scan/<service>")
def scan_status(finding_id: str, service: str):
    """Has the triggered scan finished at the service?

    urlscan only creates the result page once the scan is through, and until then it
    answers 404. Without this endpoint the link we offer right after triggering leads
    to an error page, and it looks as if the scan had failed.

    Exactly one query at the service per call. The browser does the waiting in
    between; a server waiting on somebody else's service occupies a worker and stays
    silent while doing it.
    """
    if service not in SERVICES:
        return _err(400, f"service has to be one of {sorted(SERVICES)}")
    result = _pipeline().scan_state(finding_id, service)
    if result["status"] == "unknown":
        return _err(404, "finding not found")
    if result["status"] == "none":
        return _err(404, "nothing was triggered at this service for this finding")
    return jsonify(result["scan"])


# ──────────────────────────── campaigns ─────────────────────────


@bp.get("/campaigns")
def list_campaigns():
    sort = request.args.get("sort", "newest")
    if sort not in CAMPAIGN_SORTS:
        return _err(400, f"sort has to be one of {sorted(CAMPAIGN_SORTS)}")
    try:
        limit = max(1, min(_int_arg("limit", 8), 200))
        offset = max(0, _int_arg("offset", 0))
    except ValueError as exc:
        return _err(400, str(exc))

    where, params = [], []
    if tenant := request.args.get("tenant"):
        where.append("c.tenant_id = ?")
        params.append(tenant)

    sql = (
        "SELECT c.id, c.tenant_id, c.cluster_key, c.first_seen, c.last_seen,"
        " COUNT(f.id) AS size, COALESCE(MAX(f.score), 0) AS max_score,"
        " COALESCE(MAX(f.registrar), '') AS registrar"
        " FROM campaigns c LEFT JOIN findings f ON f.campaign_id = c.id"
        + (" WHERE " + " AND ".join(where) if where else "")
        + f" GROUP BY c.id ORDER BY {CAMPAIGN_SORTS[sort]} DESC LIMIT ? OFFSET ?"
    )
    rows = _db().execute(sql, (*params, limit, offset)).fetchall()
    total = _db().execute(
        "SELECT COUNT(*) AS n FROM campaigns c" + (" WHERE " + " AND ".join(where) if where else ""),
        params,
    ).fetchone()["n"]
    return jsonify({"items": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset})


# ─────────────────────────── stats/daily ────────────────────────


@bp.get("/stats/daily")
def stats_daily():
    """Findings per day, computed from the findings themselves.

    `daily_stats` is in the schema but nobody writes to it, so the route always
    returned an empty list. The numbers are in `findings` anyway: `first_seen` is an
    ISO time in UTC, and the first ten characters are the day.
    """
    try:
        days = max(1, min(_int_arg("days", 30), 365))
    except ValueError as exc:
        return _err(400, str(exc))
    where, params = ["first_seen >= ?"], [
        (datetime.now(UTC) - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    ]
    if tenant := request.args.get("tenant"):
        where.append("tenant_id = ?")
        params.append(tenant)
    rows = _db().execute(
        "SELECT substr(first_seen, 1, 10) AS day, tenant_id,"
        " COUNT(*) AS findings_total,"
        " SUM(severity = 'info') AS findings_info,"
        " SUM(severity = 'warning') AS findings_warn,"
        " SUM(severity = 'alert') AS findings_alert,"
        " SUM(status = 'false_positive') AS false_positives"
        f" FROM findings WHERE {' AND '.join(where)}"
        " GROUP BY day, tenant_id ORDER BY day",
        params,
    ).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


# ───────────────────────────── lookup ───────────────────────────


@bp.post("/lookup")
def lookup():
    """An ad-hoc scoring. Calls the same `score_candidate` as the pipeline."""
    body = request.get_json(silent=True) or {}
    domain = str(body.get("domain", "")).strip()
    if not domain:
        return _err(400, "domain is missing")
    cand = normalize(domain)
    if cand is None:
        return _err(400, f"'{domain}' is not a scorable domain name")

    if isinstance(body.get("rules"), dict):
        # Test field with unsaved form state: check it against the schema.
        try:
            ruleset = RuleSet.model_validate(body["rules"])
        except Exception as exc:  # noqa: BLE001 - a pydantic ValidationError comes back as 422
            return _err(422, str(exc))
    else:
        ruleset = _store().get(str(body.get("tenant", "")))
        if ruleset is None:
            return _err(404, "tenant not found, pass tenant or rules")

    result = score_candidate(ruleset, cand)
    return jsonify(
        {
            "candidate": {
                "name": cand.name,
                "unicode": cand.unicode,
                "registrable": cand.registrable,
                "tld": cand.tld,
                "is_idn": cand.is_idn,
                "labels": cand.labels,
            },
            "result": result.to_dict(),
        }
    )


# ───────────────────────────── stream ───────────────────────────


@bp.get("/stream")
def stream():
    """The live SSE stream, filterable by tenant and minimum score."""
    try:
        min_score = _int_arg("min_score", 0)
    except ValueError as exc:
        return _err(400, str(exc))
    tenant = request.args.get("tenant")
    pipeline = _pipeline()
    sub = pipeline.broker.subscribe()
    keepalive = current_app.config.get("SSE_KEEPALIVE", 15.0)

    def events():
        try:
            yield ": connected\n\n"
            while True:
                try:
                    event = sub.get(timeout=keepalive)
                except queue.Empty:
                    yield ": keep-alive\n\n"
                    continue
                if tenant and event.get("tenant") != tenant:
                    continue
                if event.get("score", 0) < min_score:
                    continue
                yield f"id: {event['id']}\nevent: finding\ndata: {json.dumps(event)}\n\n"
        finally:  # a dropped connection clears the subscriber queue
            pipeline.broker.unsubscribe(sub)

    return Response(
        events(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ───────────────────────────── system ───────────────────────────


@bp.get("/system/metrics")
def system_metrics():
    return jsonify(_pipeline().metrics())


# ------------------------------ Settings ------------------------------

# What cannot be changed through the UI is listed in `settings_store.py`: everything
# to do with the deployment. A field for that would be an invitation to lock
# yourself out.


@bp.get("/settings")
def get_settings():
    return jsonify({"groups": settings_store.for_form(_db())})


@bp.route("/settings", methods=["PUT", "PATCH"])
def put_settings():
    """Change settings. Takes effect at once, no restart.

    `null` as a value resets a setting: then whatever is in `.env`, or the default in
    the code, applies again. That is something other than "typing the old value back",
    and it has to stay distinguishable.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not body:
        return _err(400, "a JSON object with at least one setting was expected")

    conn, changed = _db(), {}
    for name, raw in body.items():
        try:
            if raw is None:
                settings_store.reset(conn, name)
                changed[name] = None
            else:
                changed[name] = settings_store.put(conn, name, raw)
        except KeyError as exc:
            return _err(400, str(exc).strip("'\""))
        except (ValueError, TypeError) as exc:
            return _err(422, str(exc))

    # Into the audit trail: whoever switches enrichment on sets off queries at other
    # people's registries. That belongs on record, even without user management.
    # Secrets are not written down while doing it.
    visible = {
        k: ("(set)" if settings_store.FIELDS[k].kind == "secret" and v else v)
        for k, v in changed.items()
    }
    audit_log(
        conn, "settings.change", ", ".join(sorted(changed)),
        detail="; ".join(f"{k}={v}" for k, v in sorted(visible.items()))[:400],
        source=f"{request.remote_addr or '?'} {(request.user_agent.string or '?')[:120]}",
    )
    return jsonify({"changed": visible, "groups": settings_store.for_form(conn)})


# --------------------- Revoked CA certificates ---------------------


@bp.get("/revocations")
def revocations_list():
    """The revocation list. `source=manual` shows only the hand-entered ones."""
    from ctwatchtower.revocation import store

    conn = _db()
    entries = store.all_entries(conn)
    if (q := request.args.get("source")):
        entries = [e for e in entries if e["source"] == q]
    return jsonify({"items": entries, "numbers": store.counts(conn)})


@bp.post("/revocations")
def revocations_add():
    """Add an entry by hand."""
    from ctwatchtower.revocation import store

    body = request.get_json(silent=True) or {}
    try:
        new_id = store.add_entry(
            _db(), str(body.get("kind", "")), str(body.get("value", "")),
            name=str(body.get("name", "")), reason=str(body.get("reason", "")),
            reference=str(body.get("reference", "")),
        )
    except ValueError as exc:
        return _err(422, str(exc))
    audit_log(_db(), "revocation.add", str(new_id),
              detail=f"{body.get('kind')} {str(body.get('value'))[:80]}",
              source=f"{request.remote_addr or '?'}")
    _reload_checker()
    return jsonify({"id": new_id}), 201


@bp.route("/revocations/<int:entry_id>", methods=["PATCH", "DELETE"])
def revocations_change(entry_id: int):
    from ctwatchtower.revocation import store

    conn = _db()
    if request.method == "DELETE":
        try:
            if not store.remove_entry(conn, entry_id):
                return _err(404, "entry not found")
        except ValueError as exc:
            return _err(409, str(exc))
        audit_log(conn, "revocation.delete", str(entry_id),
                  source=f"{request.remote_addr or '?'}")
    else:
        active = bool((request.get_json(silent=True) or {}).get("active", True))
        if not store.toggle_entry(conn, entry_id, active):
            return _err(404, "entry not found")
        audit_log(conn, "revocation.toggle", str(entry_id),
                  detail="active" if active else "switched off",
                  source=f"{request.remote_addr or '?'}")
    _reload_checker()
    return jsonify({"ok": True})


@bp.get("/revocations/findings")
def revocation_findings():
    """Certificates that chain through a revoked link."""
    from ctwatchtower.revocation import store

    conn = _db()
    try:
        limit = max(1, min(_int_arg("limit", 100), 500))
    except ValueError as exc:
        return _err(400, str(exc))
    return jsonify({
        "items": store.hits(conn, limit=limit,
                                only_new=request.args.get("status") == "new"),
        "numbers": store.count_hits(conn),
    })


@bp.patch("/revocations/findings/<leaf_sha256>")
def revocation_finding_status(leaf_sha256: str):
    """Tick it off. The hit stays. The watch does not bring it back."""
    from ctwatchtower.revocation import store

    status = str((request.get_json(silent=True) or {}).get("status", ""))
    try:
        if not store.set_hit_status(_db(), leaf_sha256, status):
            return _err(404, "hit not found")
    except ValueError as exc:
        return _err(422, str(exc))
    audit_log(_db(), "revocation.finding", leaf_sha256[:16], detail=status,
              source=f"{request.remote_addr or '?'}")
    return jsonify({"ok": True})


@bp.post("/revocations/sync")
def revocations_sync():
    """Sync OneCRL now.

    The only action here that goes outwards: a GET against Mozilla's Remote Settings
    infrastructure, with the ETag we remembered. If nothing changed, a 304 comes back
    with no payload.
    """
    from ctwatchtower.revocation import onecrl, store

    conn = _db()
    # Straight from the table: `stored()` only knows the fields of the settings page,
    # and the ETag is not one of them, it belongs to the machinery.
    row = conn.execute("SELECT value FROM settings WHERE key='_onecrl_etag'").fetchone()
    etag = json.loads(row["value"]) if row else None
    try:
        result = store.sync(conn, etag if isinstance(etag, str) else None)
    except onecrl.Unreachable as exc:
        return _err(502, str(exc))
    if result.get("etag"):
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES ('_onecrl_etag',?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
            " updated_at=excluded.updated_at",
            (json.dumps(result["etag"]), datetime.now(UTC).isoformat()),
        )
        conn.commit()
    audit_log(conn, "revocation.sync", "onecrl",
              detail=f"{result['status']}, {result['imported']} entries",
              source=f"{request.remote_addr or '?'}")
    _reload_checker()
    return jsonify(result)


def _reload_checker() -> None:
    """Hand the running checker the new list, if there is one."""
    checker = current_app.config.get("REVOCATION")
    if checker is not None:
        from ctwatchtower.revocation import store

        store.load_checker(_db(), checker)


@bp.post("/system/notify-test")
def system_notify_test():
    """A test message to the configured recipients.

    Without it you only notice the typo in the mail server when the first real alert
    does not arrive, and until then you believe the monitoring would speak up.

    Exactly one mail per click, to nobody else: no batch, no retry. The daily brakes
    of the alerting stay untouched.
    """
    from ctwatchtower.notify import mail

    ok, reason = mail.configured()
    if not ok:
        return _err(409, f"mail is not set up: {reason}")
    example = {
        "tenant": "test",
        "window_seconds": settings.notify_window,
        "counts": {"alert": 1},
        "ui_url": settings.ui_base_url.rstrip("/"),
        "findings": [{
            "domain": "example-testrun.invalid", "score": 99,
            "matched": ["test message, not a real finding"],
        }],
        "truncated": 0,
    }
    try:
        mail.send("CT-Watchtower - test message", mail.text(example))
    except Exception as exc:  # noqa: BLE001 - the reason belongs in the UI
        return _err(502, f"not delivered: {exc}")
    audit_log(
        _db(), "notify.test", ", ".join(mail.recipients()),
        detail=mail.status()["route"],
        source=f"{request.remote_addr or '?'} {(request.user_agent.string or '?')[:120]}",
    )
    return jsonify({"sent_to": mail.recipients(), "route": mail.status()["route"]})


@bp.get("/system/queue-history")
def system_queue_history():
    pipeline = _pipeline()
    return jsonify({"items": list(pipeline.queue_history), "capacity": pipeline.queue_history.maxlen})
