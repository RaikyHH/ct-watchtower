"""The UI: five screens, rendered on the server.

Two decisions that explain everything else:

* **Everything that shows a domain name is rendered by the server.** That way there
  is exactly *one* place where the display rules of §12.2 apply (`render_domain`),
  and Jinja's autoescaping protects attributes like text. The browser gets finished
  HTML, never domain names as JSON it would have to assemble itself.
* **Writing actions go straight to `/api/v1`** (status, rules, tenants): the
  validation lives there. The UI only reads from the database.

Deliberately simple: no HTMX, no build step. Reloading fragments is eight lines of
`fetch` plus `innerHTML` in `app.js`; a 50 KB library for that would be ballast.
"""

from __future__ import annotations

import os
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from markupsafe import Markup, escape
from ruamel.yaml import YAML

from ctwatchtower import pseudo_tenants, settings_store
from ctwatchtower.api.routes import _row  # unpack JSON columns, one implementation is enough
from ctwatchtower.config import settings
from ctwatchtower.enrich.abuse import report as abuse_report
from ctwatchtower.enrich.deeplinks import deeplinks
from ctwatchtower.normalize.names import normalize
from ctwatchtower.rules.schema import RuleSet
from ctwatchtower.scoring.engine import score_candidate

bp = Blueprint("ui", __name__)

# Two groups with a heading each: what you watch, and what you configure. The split
# comes from the design handoff and gives the entries an order.
NAV_GROUPS = [
    ("Monitoring", [("live", "Live"), ("findings", "Findings"), ("campaigns", "Campaigns")]),
    ("Configuration", [("rules", "Rules"), ("settings", "Settings"), ("system", "System")]),
]
NAV = [entry for _, entries in NAV_GROUPS for entry in entries]
SEVERITIES = ("alert", "warning", "info")
SEV_LABEL = {"alert": "Alert", "warning": "Warning", "info": "Info"}
STATUS_LABEL = {
    "new": "New",
    "confirmed": "Confirmed",
    "false_positive": "False positive",
    "suppressed": "Suppressed",
    "reported": "Reported",
}
# ASCII characters that pass for letters (normalize/homoglyph.py, the ASCII table).
ASCII_CONFUSABLE = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"}

# --------------------- Display safety (§12.2) ---------------------


def _mark(ch: str) -> Markup:
    """A conspicuous character with its code point in the tooltip."""
    name = unicodedata.name(ch, "unnamed")
    hint = f"looks like \u201c{ASCII_CONFUSABLE[ch]}\u201d" if ch in ASCII_CONFUSABLE else name
    title = f"U+{ord(ch):04X} {name} · {hint}"
    # `mark` instead of `span`: that is semantically exactly what this is, a
    # highlight that matters. The styling inverts it (light ground, dark type) so it
    # stays readable on any background, a coloured title included.
    return Markup('<mark class="dom-hl" title="{}">{}</mark>').format(title, ch)


def render_domain(name: str, *, defang: bool | None = None) -> Markup:
    """Render a domain name as text. Never as a link to itself.

    Defanging (`[.]`) can be toggled, homoglyphs and non-ASCII characters are marked.
    Every character goes through `escape()`; domain names are hostile input, even when
    they come out of our own database.
    """
    if defang is None:
        defang = defang_on()
    has_alpha = any(c.isalpha() for c in name)
    out: list[Markup] = []
    for ch in name:
        if ch == "." and defang:
            out.append(Markup('<span class="defang">[.]</span>'))
        elif ord(ch) > 127 or (has_alpha and ch in ASCII_CONFUSABLE):
            out.append(_mark(ch))
        else:
            out.append(escape(ch))
    return Markup("").join(out)


def defang_on() -> bool:
    """`UI_DEFANG_DEFAULT` (default: on), toggled per browser with a cookie."""
    cookie = request.cookies.get("ctw_defang")
    if cookie in ("0", "1"):
        return cookie == "1"
    return os.environ.get("UI_DEFANG_DEFAULT", "true").lower() not in ("0", "false", "no")


def defang_text(name: str) -> str:
    """The plain text variant, for attributes (copying, tooltips)."""
    return name.replace(".", "[.]") if defang_on() else name


def analysis_links(f: dict) -> list[tuple[str, str]]:
    """Deeplinks from `config/deeplinks.yaml`. Analysis services only (§12.2).

    Plain links, no server-side call: no network traffic happens here, only the user's
    click opens a new tab. `deeplinks()` leaves out links whose placeholders are empty,
    and drops patterns with a placeholder in the host.
    """
    a_records = f.get("a_records") or []
    return deeplinks(f["domain"], f.get("registrable") or "", a_records[0] if a_records else "")


def rel_time(value: str | None) -> str:
    if not value:
        return "-"
    try:
        then = datetime.fromisoformat(value)
    except ValueError:
        return value
    if then.tzinfo is None:
        then = then.replace(tzinfo=UTC)
    secs = int((datetime.now(UTC) - then).total_seconds())
    if secs < 60:
        return "just now"
    for limit, div, unit in ((3600, 60, "min"), (86400, 3600, "h"), (2592000, 86400, "d")):
        if secs < limit:
            return f"{secs // div} {unit} ago"
    return then.strftime("%Y-%m-%d")


# ---------------------------- Data access ----------------------------


def _db():
    return current_app.config["DB"]


def _store():
    return current_app.config["RULES"]


def _tenants() -> list[Any]:
    """Every tenant, disabled ones included. The switcher marks them."""
    return list(_store().all_rulesets)


def _active_tenant() -> str | None:
    """The selected tenant. A real one, or one of the two pseudo tenants."""
    ids = [rs.tenant.id for rs in _tenants()]
    wanted = request.args.get("t") or request.cookies.get("ctw_tenant")
    if wanted in ids or pseudo_tenants.is_pseudo(wanted):
        return wanted
    return ids[0] if ids else None


def _filter() -> str | None:
    """What goes into a query as the tenant filter.

    For "all tenants" that is `None`. The queries then leave the filter out and sum
    up over everything.
    """
    return pseudo_tenants.query_filter(_active_tenant())


# What the finding list may be sorted by, and nothing else.
SORTABLE_COLUMNS = {
    "first_seen": "first_seen",
    "severity": "score",  # severity follows the score, so the same order
    "score": "score",
    "domain": "domain",
    "tld": "tld",
    "registrar": "registrar",
    "status": "status",
}


def query_findings(
    tenant: str | None,
    *,
    severity: str | None = None,
    min_score: int | None = None,
    q: str | None = None,
    sort: str | None = None,
    limit: int = 50,
) -> list[dict]:
    where, params = [], []
    if tenant:
        where.append("tenant_id = ?")
        params.append(tenant)
    if severity in SEVERITIES:
        where.append("severity = ?")
        params.append(severity)
    if min_score:
        where.append("score >= ?")
        params.append(min_score)
    if q:
        where.append("(domain LIKE ? OR unicode_form LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    sql = "SELECT * FROM findings"
    if where:
        sql += " WHERE " + " AND ".join(where)
    # A fixed list instead of text passed through: a column name from the request
    # would be an invitation to append arbitrary SQL.
    column = SORTABLE_COLUMNS.get(sort or "", "first_seen")
    sql += f" ORDER BY {column} DESC, id DESC LIMIT ?"
    return [_row(r) for r in _db().execute(sql, (*params, max(1, min(limit, 500))))]


def severity_counts(tenant: str | None) -> dict[str, int]:
    sql = "SELECT severity, COUNT(*) AS n FROM findings"
    params: list[Any] = []
    if tenant:
        sql += " WHERE tenant_id = ?"
        params.append(tenant)
    rows = _db().execute(sql + " GROUP BY severity", params).fetchall()
    counts = {s: 0 for s in SEVERITIES}
    for row in rows:
        counts[row["severity"]] = row["n"]
    return counts


def first_match(finding: dict) -> str:
    explanation = finding.get("explanation") or {}
    matched = explanation.get("matched") if isinstance(explanation, dict) else None
    return matched[0] if matched else "-"


# -------------------------- The shared context --------------------------


def screen_title(text: str) -> Markup:
    """The page title as a fourteen-segment display.

    Behind it sit ghost characters `~` in the colour of unlit segments, so you can see
    that the display has more places than are lit right now. Without them a short word
    looks like a fragment of text instead of a readout.
    """
    visible = escape(text.upper())
    return Markup(
        f'<div class="screen-title"><span class="ghost">{"~" * len(text)}</span>'
        f'<span class="lit">{visible}</span></div>'
    )


def dseg(value, level: str = "", size: str = "") -> Markup:
    """A number as a seven-segment display, with unlit segments behind it.

    The "888" sit under the number and show through as dark segments. The number
    itself is right-aligned on top, so the places stay put.
    """
    text = escape(str(value))
    style = f' style="font-size:{size};"' if size else ""
    css_class = f"dseg {level}".strip()
    return Markup(
        f'<span class="{css_class}"{style}><span class="ghost">{"8" * len(str(value))}</span>'
        f'<span class="lit">{text}</span></span>'
    )


@bp.app_context_processor
def _globals() -> dict:
    return {
        "screen_title": screen_title,
        "dseg": dseg,
        "render_domain": render_domain,
        "defang_text": defang_text,
        "defang_on": defang_on,
        "rel_time": rel_time,
        "analysis_links": analysis_links,
        "SEV_LABEL": SEV_LABEL,
        "STATUS_LABEL": STATUS_LABEL,
        "first_match": first_match,
        # The button is always visible but disabled while the analysis is switched
        # off. Otherwise you look in vain for a function that does exist.
        "SCAN_SERVICES": (("scanmalware", "scanmalware.com"), ("urlscan", "urlscan.io")),
        "scan_enabled": settings.scan_enabled,
        "scan_visibility": settings.scan_visibility,
        "scan_daily": settings.scan_daily,
    }


def shell(**extra: Any) -> dict:
    tenants = _tenants()
    active = _active_tenant()
    is_revoked_watch = active == pseudo_tenants.REVOKED
    return {
        "nav": NAV,
        "nav_groups": NAV_GROUPS,
        "screen": request.endpoint.split(".")[-1] if request.endpoint else "",
        "tenants": [t.tenant for t in tenants],
        "pseudo": pseudo_tenants.PSEUDO,
        "active": active,
        "active_name": pseudo_tenants.name(active)
        or next((t.tenant.name for t in tenants if t.tenant.id == active), None),
        # The revoked watch has counters of its own. There are no severities there, a
        # certificate is revoked or it is not.
        "counts": _revocation_counts() if is_revoked_watch else severity_counts(_filter()),
        "revoked_watch": is_revoked_watch,
        **extra,
    }


def _revocation_counts() -> dict[str, int]:
    """The three tiles at the top, repurposed: new, checked, benign."""

    rows = _db().execute("SELECT status, count(*) n FROM ca_hits GROUP BY 1").fetchall()
    by_status = {z["status"]: z["n"] for z in rows}
    return {
        "alert": by_status.get("new", 0),
        "warning": by_status.get("checked", 0),
        "info": by_status.get("benign", 0),
    }


def _screen(name: str, **extra: Any):
    """The empty state: without tenants every screen leads into the create dialog.

    Except for the revoked watcher. It hangs off no tenant. Whoever only wants to
    watch the web PKI should be able to do that without a single ruleset.
    """
    ctx = shell(**extra)
    if not ctx["tenants"] and name != "rules" and not ctx["revoked_watch"]:
        return redirect(url_for("ui.rules"))
    return render_template(f"{name}.html", **ctx)


# -------------------------------- Screens --------------------------------


@bp.get("/")
def index():
    return redirect(url_for("ui.live"))


@bp.get("/live")
def live():
    return _screen("live")


@bp.get("/findings")
def findings():
    return _screen("findings")


@bp.get("/campaigns")
def campaigns():
    return _screen("campaigns")


@bp.get("/system")
def system():
    return _screen("system")


# The endpoint is called `settings`, the function is not: the navigation builds its
# links from the id, and `settings` as a function name would shadow the config object.
@bp.get("/settings", endpoint="settings")
def settings_screen():
    """Everything that steers the operation, without having to go to the container."""
    from ctwatchtower.revocation import store

    conn = _db()
    row = conn.execute("SELECT value, updated_at FROM settings WHERE key='_onecrl_etag'").fetchone()
    return render_template(
        "settings.html",
        **shell(
            groups=settings_store.for_form(conn),
            revocation=store.all_entries(conn),
            revocation_counts=store.counts(conn),
            revocation_synced=row["updated_at"][:16].replace("T", " ") if row else None,
        ),
    )


@bp.get("/rules")
def rules():
    active = _active_tenant()
    ruleset = _store().get(active) if active else None
    return render_template(
        "rules.html",
        # The threshold slider is no use while the main switch is off, and that has to
        # be said in the place where you move it.
        auto_on=settings.enrich_auto and settings.enrich_enabled,
        **shell(form=rule_form(ruleset) if ruleset else None),
    )


# ---------------------------- Fragments ----------------------------


def _rows_args() -> dict:
    try:
        min_score = int(request.args.get("min_score") or 0)
    except ValueError:
        min_score = 0
    return {
        "severity": request.args.get("severity"),
        "min_score": min_score,
        "q": (request.args.get("q") or "").strip() or None,
        "sort": request.args.get("sort"),
    }


def _revocation_rows_fragment(*, limit: int, as_table: bool = False):
    """The certificates of revoked issuers, in the shape of the finding list.

    Its own template instead of bending the existing one: there is no score and no
    severity here, but the chain link that matched. Pressing that into the same table
    would mean leaving columns empty and bending the meaning of words.
    """
    from ctwatchtower.revocation import store

    args = _rows_args()
    hits = store.hits(_db(), limit=limit)
    if search := (args.get("q") or "").lower():
        hits = [f for f in hits
                 if search in " ".join(f["names"]).lower()
                 or search in (f["revoked_issuer"] or "").lower()]
    template_name = "frag_revocation_table.html" if as_table else "frag_revocation_live.html"
    return render_template(template_name, hits=hits, filtered=bool(search))


@bp.get("/ui/spectrum")
def spectrum_frag():
    """The findings spectrum for Live (per minute) and Findings (per day)."""
    resolution = "day" if request.args.get("a") == "day" else "minute"
    values = findings_per_bucket(_filter(), resolution=resolution)
    return render_template(
        "frag_spectrum.html",
        values=values,
        # Days carry more height than minutes. A day bundles what comes past
        # one at a time in a minute, and deserves the finer gradation.
        chart=minute_chart(values, segments=8 if resolution == "day" else 4),
        days_mode=resolution == "day",
    )


@bp.get("/ui/live-rows")
def live_rows():
    if _active_tenant() == pseudo_tenants.REVOKED:
        return _revocation_rows_fragment(limit=60)
    args = _rows_args()
    rows = query_findings(_filter(), limit=60, **args)
    return render_template("frag_live_rows.html", rows=rows)


@bp.get("/ui/findings-rows")
def findings_rows():
    if _active_tenant() == pseudo_tenants.REVOKED:
        return _revocation_rows_fragment(limit=200, as_table=True)
    args = _rows_args()
    rows = query_findings(_filter(), limit=200, **args)
    # "No findings" with a filter switched on is misleading, so the template says
    # both separately.
    filtered = bool(args.get("severity") or args.get("q") or args.get("min_score"))
    return render_template("frag_findings_rows.html", rows=rows, filtered=filtered)


@bp.get("/ui/finding/<finding_id>")
def finding_detail(finding_id: str):
    row = _db().execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if row is None:
        return "finding not found", 404
    hit = _row(row)
    # Only the draft. Nothing is sent. The user reads and edits it in their mail
    # program before sending it (§16.3: a score is not a verdict).
    report_draft = abuse_report(hit, settings.abuse_language)
    return render_template(
        "frag_detail.html", f=hit, abuse=report_draft, exoneration=_entlastung(hit)
    )


def _entlastung(hit: dict) -> dict | None:
    """Does the enrichment speak against the finding? Then the panel says so as a note.

    Such a finding used to disappear by itself. That came of the enrichment overwriting
    the score, and that is exactly what it does not do any more: a 90 turned into a 15
    while you looked at it, and nobody knew whether they had misread it. Instead of
    the quiet disappearance there is a sentence here with a button next to it; the
    decision is made by hand.
    """
    fresh = hit.get("score_enriched")
    old = hit.get("score") or 0
    if fresh is None or hit.get("status") in ("false_positive", "confirmed", "reported"):
        return None
    rs = _store().get(hit.get("tenant_id") or "")
    threshold = rs.thresholds.persist if rs else 0
    # Either the finding drops below the threshold from which anything is stored at
    # all, or it loses at least a third of its points.
    if not (fresh < threshold <= old or old - fresh >= max(20, old // 3)):
        return None
    reason = (hit.get("enrich_note") or "").partition(":")[2].strip()
    return {"score": fresh, "reason": reason, "below_threshold": fresh < threshold}


@bp.get("/ui/campaigns")
def campaigns_frag():
    tenant = _filter()
    sort = {"newest": "c.first_seen", "largest": "size", "score": "max_score"}.get(
        request.args.get("sort", "newest"), "c.first_seen"
    )
    limit = 8 if request.args.get("all") != "1" else 200
    rows = _db().execute(
        "SELECT c.id, c.cluster_key, c.first_seen, c.last_seen, COUNT(f.id) AS size,"
        " COALESCE(MAX(f.score), 0) AS max_score, COALESCE(MAX(f.registrar), '') AS registrar"
        " FROM campaigns c LEFT JOIN findings f ON f.campaign_id = c.id"
        " WHERE c.tenant_id = ? GROUP BY c.id"
        f" ORDER BY {sort} DESC LIMIT ?",
        (tenant, limit + 1),
    ).fetchall()
    more = len(rows) > limit
    cards = []
    for row in rows[:limit]:
        members = _db().execute(
            "SELECT id, domain, severity, score FROM findings"
            " WHERE campaign_id = ? ORDER BY score DESC",
            (row["id"],),
        ).fetchall()
        counts = {s: sum(1 for m in members if m["severity"] == s) for s in SEVERITIES}
        top = "alert" if counts["alert"] else ("warning" if counts["warning"] else "info")
        cards.append(
            {
                **dict(row),
                "counts": counts,
                "top": top,
                # With `id`, so every name can open its detail panel. Before this you
                # saw the cluster and could not get into it.
                "members": [dict(m) for m in members[:4]],
                "rest": max(0, len(members) - 4),
            }
        )
    return render_template("frag_campaigns.html", cards=cards, more=more)


@bp.get("/ui/system")
def system_frag():
    pipeline = current_app.config["PIPELINE"]
    metrics = pipeline.metrics()
    # `queue_history` keeps samples as {"depth_pct": ..., "t": ...}; the graph wants numbers.
    history = [p["depth_pct"] for p in pipeline.queue_history] or [metrics["queue_depth_pct"]]
    return render_template(
        "frag_system.html",
        m=metrics,
        chart=queue_chart(history),
        # Active tenants only: a disabled one serves no feed. `shadow` hangs off the
        # ruleset, not off the tenant, and is merged in here.
        feed_tenants=[
            {"id": rs.tenant.id, "name": rs.tenant.name, "shadow": rs.shadow}
            for rs in _store().rulesets
        ],
        feeds_token=bool(settings.api_token),
    )


SPECTRUM_COLUMNS = 30
SPECTRUM_SEGMENTS = 10


def queue_chart(history: list[float]) -> list[list[str]]:
    """The queue history as a spectrum instead of a line.

    Thirty columns of ten segments, lit from the bottom up. The upper segments carry
    their meaning as colour: from 50 % it throttles (segments 6 to 8, amber), from
    80 % the ingest pauses (segments 9 and 10, red). A line chart would demand that
    you read the scale; here you see the zone.

    Returns the segment classes per column, from top to bottom.
    """
    values = list(history)[-SPECTRUM_COLUMNS:]
    values = [0.0] * (SPECTRUM_COLUMNS - len(values)) + values

    columns = []
    for value in values:
        height = round(max(0.0, min(100.0, value)) / 100 * SPECTRUM_SEGMENTS)
        segments = []
        for level in range(SPECTRUM_SEGMENTS, 0, -1):
            if level > height:
                segments.append("off")
            elif level > 8:
                segments.append("alert")
            elif level > 5:
                segments.append("warn")
            else:
                segments.append("on")
        columns.append(segments)
    return columns


# Per resolution: how long the time key in `first_seen` is and how far one column
# reaches. `first_seen` is an ISO time in UTC, so `substr` is enough.
RESOLUTIONS = {
    "minute": (16, timedelta(minutes=1), "%Y-%m-%dT%H:%M"),
    "day": (10, timedelta(days=1), "%Y-%m-%d"),
}


def findings_per_bucket(
    tenant: str | None, *, resolution: str = "minute", now: datetime | None = None
) -> list[int]:
    """Findings per minute (last 30) or per day (last 30), oldest first.

    No separate time series needed. The numbers are in `first_seen`. A period without
    a finding is a zero, not a gap: otherwise the spectrum would squeeze quiet times
    together and show a history that never happened.
    """
    length, step, form = RESOLUTIONS[resolution]
    now = now or datetime.now(UTC)
    # Truncate to the start of the period: otherwise the last column would wander
    # with the clock and count 40 seconds one moment and 60 the next.
    start_of = datetime.strptime(now.strftime(form), form).replace(tzinfo=UTC)
    start = start_of - step * (SPECTRUM_COLUMNS - 1)
    sql = (
        f"SELECT substr(first_seen, 1, {length}) AS bucket, COUNT(*) AS n FROM findings"
        " WHERE first_seen >= ?"
    )
    params: list[Any] = [start.strftime(form)]
    if tenant:
        sql += " AND tenant_id = ?"
        params.append(tenant)
    counted = {r["bucket"]: r["n"] for r in _db().execute(sql + " GROUP BY bucket", params)}
    return [counted.get((start + step * i).strftime(form), 0) for i in range(SPECTRUM_COLUMNS)]


def minute_chart(values: list[int], segments: int = 4) -> list[list[str]]:
    """Columns without zone colours: the highest value is the scale, not a fixed
    limit. Red for "many findings" would be a judgement the number does not carry.

    Bottom to top. The column is `flex-direction: column-reverse`, so the first
    segment sits at the bottom.
    """
    highest = max(values) or 1
    columns = []
    for value in values:
        # Every finding lights at least one segment: a minute with one finding must
        # not look like a minute without.
        height = min(segments, -(-value * segments // highest)) if value else 0
        columns.append(["on" if level <= height else "" for level in range(1, segments + 1)])
    return columns


# --------------------------- Rules: the form ---------------------------


def _split(groups: list, tenant_id: str) -> tuple[list, list]:
    """(inherited, own) by `source`: own is exactly what came out of `<id>.yaml`.

    Works for models (`group.source`) as well as for `model_dump()` dicts."""
    own_file = f"{tenant_id}.yaml"
    inherited, own = [], []
    for group in groups:
        src = group.get("source") if isinstance(group, dict) else group.source
        (own if src == own_file else inherited).append(group)
    return inherited, own


def _own_groups(tenant_id: str) -> dict[str, list[dict]]:
    """The tenant's own groups raw from `<id>.yaml`, the way they sit in the file.

    The form only changes `terms`/`list` and `weight` in them and sends the group back
    otherwise unchanged. Fields it does not know (`exclude`, `owned_domains`, `match`,
    future ones) survive that way without anybody maintaining a field list here. From
    the file rather than the model: no filled-in defaults, no `source`.
    """
    path = Path(current_app.config["RULES_DIR"]) / f"{tenant_id}.yaml"
    doc = YAML(typ="safe").load(path.read_text(encoding="utf-8")) if path.is_file() else None
    doc = doc if isinstance(doc, dict) else {}
    return {
        "anchors": list(doc.get("anchors") or []),
        "lures": list(doc.get("lures") or []),
        "tlds": list((doc.get("tlds") or {}).get("groups") or []),
        # Not in groups but on the ruleset: what should never be reported, and custom
        # rules. Raw from the file as well. Only the own entries are editable here,
        # the form shows inherited ones next to them as read-only.
        "allowlist": dict(doc.get("allowlist") or {}),
        # Rules made of several conditions. The form in which a public authority can
        # be captured at all ("place name AND administrative term"). The form could
        # display them from the start; they were not delivered, and the tab then said
        # "0 rules" although the file held some.
        "rules": list(doc.get("rules") or []),
        "custom": list(doc.get("custom") or []),
    }


def rule_form(ruleset: RuleSet) -> dict:
    tid = ruleset.tenant.id

    def terms(groups, attr: str = "terms") -> list[str]:
        return sorted({t for gr in groups for t in getattr(gr, attr)})

    own = _own_groups(tid)
    own_suppress = (own["allowlist"].get("suppress") or {})

    def without_own(every: list[str], mine: list[str]) -> list[str]:
        return sorted(set(every) - set(mine or []))

    return {
        "tenant": ruleset.tenant,
        "shadow": ruleset.shadow,
        "thresholds": ruleset.thresholds,
        "scoring": ruleset.scoring,
        # The effective structure thresholds, not those of the tenant's own file: they
        # come from the default plus includes plus the file. Whoever moves one here
        # writes the value into their own file and pins it, which is the intention.
        "structure": ruleset.structure,
        "own": own,
        "inherited_anchors": terms(_split(ruleset.anchors, tid)[0]),
        "inherited_lures": terms(_split(ruleset.lures, tid)[0]),
        "inherited_tlds": terms(_split(ruleset.tlds.groups, tid)[0], "list_"),
        "inherited_suppress": without_own(
            [*ruleset.allowlist.suppress.exact, *ruleset.allowlist.suppress.suffix],
            [*(own_suppress.get("exact") or []), *(own_suppress.get("suffix") or [])],
        ),
    }


@bp.post("/ui/lookup")
def lookup_frag():
    """The test field. Scores with the *unsaved* form state.

    Deliberately simple: calls the same `score_candidate` as the pipeline and
    `/api/v1/lookup`; rendered here so the domain name goes through `render_domain`.
    """
    body = request.get_json(silent=True) or {}
    domain = str(body.get("domain", "")).strip()
    ruleset = _store().get(str(body.get("tenant") or ""))
    if ruleset is None:
        return jsonify({"error": "tenant not found"}), 404
    cand = normalize(domain)
    if cand is None:
        return render_template("frag_lookup.html",
                               error=f"\u201c{domain}\u201d is not a scorable name")

    doc = ruleset.model_dump(by_alias=True)
    patch = body.get("patch") if isinstance(body.get("patch"), dict) else {}
    tid = ruleset.tenant.id
    for key in ("anchors", "lures"):
        if key in patch:
            doc[key] = _split(doc.get(key) or [], tid)[0] + list(patch.pop(key) or [])
    if "groups" in (patch.get("tlds") or {}):
        inherited, _ = _split(doc["tlds"]["groups"], tid)
        doc["tlds"]["groups"] = inherited + list(patch["tlds"].pop("groups") or [])
    _merge(doc, patch)

    try:
        test_rules = RuleSet.model_validate(doc)
    except Exception as exc:  # noqa: BLE001 - the form state can be invalid
        return render_template("frag_lookup.html", error=str(exc).splitlines()[0])
    return render_template(
        "frag_lookup.html", cand=cand, result=score_candidate(test_rules, cand), error=None
    )


def _merge(base: dict, patch: dict) -> dict:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base
