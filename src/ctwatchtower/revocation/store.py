"""The revocation list in the database: read it, maintain it, sync it with OneCRL."""

from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime

from ctwatchtower.revocation import onecrl
from ctwatchtower.revocation.checker import Checker

log = logging.getLogger(__name__)

KINDS = ("sha256", "spki", "issuer_serial")


def all_entries(conn: sqlite3.Connection, *, only_active: bool = False) -> list[dict]:
    where = " WHERE active = 1" if only_active else ""
    rows = conn.execute(
        f"SELECT id, source, kind, value, name, reason, reference, active, created_at"
        f" FROM ca_revocations{where} ORDER BY source, name, id"
    ).fetchall()
    return [dict(r) for r in rows]


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    """How many entries per origin. For the display, without loading everything."""
    rows = conn.execute(
        "SELECT source, count(*) n, sum(active) a FROM ca_revocations GROUP BY source"
    ).fetchall()
    out = {r["source"]: r["n"] for r in rows}
    out["active"] = sum(r["a"] or 0 for r in rows)
    out["total"] = sum(r["n"] for r in rows)
    return out


def add_entry(conn: sqlite3.Connection, kind: str, value: str, *,
                name: str = "", reason: str = "", reference: str = "") -> int:
    """Add an entry by hand. Returns its id."""
    if kind not in KINDS:
        raise ValueError(f"kind has to be one of {KINDS}")
    value = value.strip()
    if not value:
        raise ValueError("value is missing")
    if kind == "sha256":
        # With colons, without, upper or lower case: internally always the same.
        bare = value.replace(":", "").replace(" ", "").lower()
        if len(bare) != 64 or any(c not in "0123456789abcdef" for c in bare):
            raise ValueError("a SHA-256 is 64 hex characters")
        value = bare
    elif "|" not in value:
        raise ValueError(f"`{kind}` expects two base64 values, separated by |")

    conn.execute(
        "INSERT INTO ca_revocations (source, kind, value, name, reason, reference, created_at)"
        " VALUES ('manual',?,?,?,?,?,?)"
        " ON CONFLICT(source, kind, value) DO UPDATE SET"
        " name=excluded.name, reason=excluded.reason, reference=excluded.reference, active=1",
        (kind, value, name.strip(), reason.strip(), reference.strip(),
         datetime.now(UTC).isoformat()),
    )
    conn.commit()
    row = conn.execute(
        "SELECT id FROM ca_revocations WHERE source='manual' AND kind=? AND value=?",
        (kind, value),
    ).fetchone()
    return int(row["id"])


def remove_entry(conn: sqlite3.Connection, entry_id: int) -> bool:
    """Own entries only. Anything from OneCRL would be back after the next sync, so
    whoever wants rid of it switches it off instead of deleting it."""
    row = conn.execute(
        "SELECT source FROM ca_revocations WHERE id=?", (entry_id,)
    ).fetchone()
    if row is None:
        return False
    if row["source"] != "manual":
        raise ValueError("entries from a fetched list can only be switched off")
    conn.execute("DELETE FROM ca_revocations WHERE id=?", (entry_id,))
    conn.commit()
    return True


def toggle_entry(conn: sqlite3.Connection, entry_id: int, active: bool) -> bool:
    cur = conn.execute("UPDATE ca_revocations SET active=? WHERE id=?",
                       (int(active), entry_id))
    conn.commit()
    return cur.rowcount > 0


def sync(conn: sqlite3.Connection, etag: str | None = None) -> dict:
    """Fetch OneCRL and replace everything stored under that origin.

    Replace, not merge: a revocation that was withdrawn has to disappear. Own
    entries stay untouched, they sit under the origin `manual`.
    """
    rulesets, fresh_etag = onecrl.fetch(etag)
    if not rulesets:
        return {"status": "unchanged", "etag": fresh_etag,
                "imported": 0, "stored": counts(conn).get("onecrl", 0)}

    entries = onecrl.entries(rulesets)
    now = datetime.now(UTC).isoformat()
    conn.execute("DELETE FROM ca_revocations WHERE source='onecrl'")
    conn.executemany(
        "INSERT OR IGNORE INTO ca_revocations"
        " (source, kind, value, name, reason, reference, created_at)"
        " VALUES ('onecrl',?,?,?,?,?,?)",
        [(e["kind"], e["value"], e.get("name", ""), e["reason"], e.get("reference", ""), now)
         for e in entries],
    )
    conn.commit()
    log.info("OneCRL synced: %d entries imported", len(entries))
    return {"status": "updated", "etag": fresh_etag,
            "imported": len(entries), "stored": counts(conn).get("onecrl", 0)}


def load_checker(conn: sqlite3.Connection, checker: Checker | None = None) -> Checker:
    """Fill a checker with the current list."""
    p = checker or Checker()
    p.load(all_entries(conn, only_active=True))
    return p


# --------------------------------- Hits ---------------------------------


def report_hit(conn: sqlite3.Connection, record: dict) -> bool:
    """Record a hit. `True` if it was new.

    The same certificate arrives several times in the CT stream; it gets counted,
    but it appears once. The status survives: whoever ticked a hit off does not
    get it back on the next run.
    """
    import json

    now = datetime.now(UTC).isoformat()
    conn.execute(
        "INSERT INTO ca_hits (leaf_sha256, first_seen, last_seen, revoked_issuer, link_sha256,"
        " link_subject, reason, reference, names, names_total, chain)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(leaf_sha256) DO UPDATE SET"
        " last_seen=excluded.last_seen, hit_count=ca_hits.hit_count+1",
        (
            (record.get("leaf_sha256") or "").replace(":", "").lower(),
            now, now,
            record.get("revoked_issuer", ""), record.get("link_sha256", ""),
            record.get("link_subject", ""), record.get("reason", ""),
            record.get("reference", ""),
            json.dumps(record.get("names") or [], ensure_ascii=False),
            int(record.get("names_total") or 0),
            json.dumps(record.get("chain") or [], ensure_ascii=False),
        ),
    )
    conn.commit()
    # rowcount is 1 on INSERT and 1 on UPDATE too, so decide by `hit_count`.
    row = conn.execute("SELECT hit_count FROM ca_hits WHERE leaf_sha256=?",
                         ((record.get("leaf_sha256") or "").replace(":", "").lower(),)).fetchone()
    return bool(row and row["hit_count"] == 1)


def hits(conn: sqlite3.Connection, *, limit: int = 100, only_new: bool = False) -> list[dict]:
    import json

    where = " WHERE status = 'new'" if only_new else ""
    rows = conn.execute(
        f"SELECT * FROM ca_hits{where} ORDER BY last_seen DESC LIMIT ?", (limit,)
    ).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        for field in ("names", "chain"):
            try:
                d[field] = json.loads(d[field])
            except (ValueError, TypeError):
                d[field] = []
        out.append(d)
    return out


def count_hits(conn: sqlite3.Connection) -> dict[str, int]:
    row = conn.execute(
        "SELECT count(*) total, sum(status='new') new FROM ca_hits"
    ).fetchone()
    return {"total": row["total"] or 0, "new": row["new"] or 0}


def set_hit_status(conn: sqlite3.Connection, leaf_sha256: str, status: str) -> bool:
    if status not in ("new", "checked", "benign"):
        raise ValueError("status has to be new, checked or benign")
    cur = conn.execute("UPDATE ca_hits SET status=? WHERE leaf_sha256=?",
                       (status, leaf_sha256.replace(":", "").lower()))
    conn.commit()
    return cur.rowcount > 0
