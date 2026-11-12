"""SQLite persistence (§9.2, cut down to tenants/findings/campaigns/daily_stats).

Nothing that stays below `persist` is stored (§9.1); raw certificates never reach
the database. For the original there is crt.sh plus `ct_log_index`.
"""

import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ctwatchtower.config import settings
from ctwatchtower.normalize.names import CandidateName, CertContext

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    tlp            TEXT NOT NULL DEFAULT 'clear',
    ruleset_hash   TEXT,
    ruleset_loaded TEXT,
    config         TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS campaigns (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cluster_key TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (tenant_id, cluster_key)
);

CREATE TABLE IF NOT EXISTS findings (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    domain               TEXT NOT NULL,
    registrable          TEXT NOT NULL,
    tld                  TEXT NOT NULL,
    is_idn               INTEGER NOT NULL DEFAULT 0,
    is_wildcard          INTEGER NOT NULL DEFAULT 0,
    unicode_form         TEXT,

    score                INTEGER NOT NULL,
    score_phase1         INTEGER NOT NULL,
    severity             TEXT NOT NULL,
    severity_at_creation TEXT NOT NULL,
    explanation          TEXT NOT NULL DEFAULT '{}',

    first_seen           TEXT NOT NULL,
    last_seen            TEXT NOT NULL,
    cert_count           INTEGER NOT NULL DEFAULT 1,
    hit_count            INTEGER NOT NULL DEFAULT 1,

    cert_sha256          TEXT,
    cert_not_before      TEXT,
    cert_not_after       TEXT,
    issuer_o             TEXT,
    san_count            INTEGER,
    related_names        TEXT NOT NULL DEFAULT '[]',
    ct_log_id            TEXT,
    ct_log_index         INTEGER,

    enrich_state         TEXT NOT NULL DEFAULT 'pending',
    enriched_at          TEXT,
    enrich_attempts      INTEGER NOT NULL DEFAULT 0,
    registrar            TEXT,
    registrar_id         INTEGER,
    domain_created       TEXT,
    domain_changed       TEXT,
    domain_expires       TEXT,
    epp_status           TEXT,
    nameservers          TEXT,
    a_records            TEXT,
    has_mx               INTEGER,
    asn                  INTEGER,
    as_org               TEXT,
    country              TEXT,
    vt_detections        INTEGER,

    status               TEXT NOT NULL DEFAULT 'new',
    status_note          TEXT,
    status_at            TEXT,
    escalated_at         TEXT,
    campaign_id          TEXT REFERENCES campaigns(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_tenant_seen ON findings (tenant_id, first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_sev  ON findings (tenant_id, severity, first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_dedupe      ON findings (tenant_id, registrable, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_registrable ON findings (registrable);
CREATE INDEX IF NOT EXISTS idx_findings_campaign    ON findings (campaign_id);

CREATE TABLE IF NOT EXISTS daily_stats (
    day             TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    certs_seen      INTEGER NOT NULL DEFAULT 0,
    prefilter_pass  INTEGER NOT NULL DEFAULT 0,
    findings_total  INTEGER NOT NULL DEFAULT 0,
    findings_info   INTEGER NOT NULL DEFAULT 0,
    findings_warn   INTEGER NOT NULL DEFAULT 0,
    findings_alert  INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0,
    top_tlds        TEXT,
    top_registrars  TEXT,
    PRIMARY KEY (day, tenant_id)
);

-- Enrichment cache (§7.1): the key is the registrable domain, the content is
-- only the already filtered result (§16.2), never the raw response.
CREATE TABLE IF NOT EXISTS enrich_cache (
    source     TEXT NOT NULL,
    key        TEXT NOT NULL,
    data       TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (source, key)
);

-- Daily counters for external queries (hard caps). In the database, so that a
-- container restart does not reset the cap.
CREATE TABLE IF NOT EXISTS enrich_quota (
    day   TEXT NOT NULL,
    key   TEXT NOT NULL,
    n     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, key)
);

-- Irreversible actions. In the database on purpose and not in the application log:
-- the access log lives in the container and is gone with the next rebuild. Which is
-- exactly when it is missing. When a tenant and all its findings had disappeared,
-- there was no way left to tell where the request came from.
CREATE TABLE IF NOT EXISTS audit (
    at      TEXT NOT NULL,
    action  TEXT NOT NULL,
    target  TEXT NOT NULL,
    detail  TEXT,
    source  TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at DESC);

-- Settings that were changed through the UI. Only the changed ones: whatever is not
-- in here comes from `.env` or from the defaults in the code. That way it stays
-- readable what somebody deliberately moved, and an entry can be deleted instead
-- of having to be typed back to its default.
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Revoked CA certificates. Two origins in one table:
--   `onecrl`   fetched automatically from Mozilla's revocation list, replaced on
--              every sync. Hand-edited entries of this origin would be gone again
--              on the next run.
--   `manual`   entered by hand, stays put.
-- `kind` says how to read the value: `sha256` (the certificate itself), `spki`
-- (subject|SHA-256 of the SubjectPublicKeyInfo, both base64) or `issuer_serial`
-- (issuer|serial number, both base64). The last two are the forms OneCRL
-- addresses certificates by.
CREATE TABLE IF NOT EXISTS ca_revocations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    source     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL DEFAULT '',
    reference  TEXT NOT NULL DEFAULT '',
    active     INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    UNIQUE (source, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_ca_revocations_source ON ca_revocations(source);

-- Certificates that chain through a revoked link. No tenant: this hangs off no
-- brand but off the web PKI. So no score and no severity either. There is nothing
-- to weigh up, the certificate is revoked or it is not.
-- `leaf_sha256` is the key: the same certificate arrives several times in the CT
-- stream but should appear here once.
CREATE TABLE IF NOT EXISTS ca_hits (
    leaf_sha256   TEXT PRIMARY KEY,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    hit_count      INTEGER NOT NULL DEFAULT 1,
    revoked_issuer TEXT NOT NULL DEFAULT '',
    link_sha256    TEXT NOT NULL DEFAULT '',
    link_subject   TEXT NOT NULL DEFAULT '',
    reason         TEXT NOT NULL DEFAULT '',
    reference      TEXT NOT NULL DEFAULT '',
    names          TEXT NOT NULL DEFAULT '[]',
    names_total    INTEGER NOT NULL DEFAULT 0,
    chain          TEXT NOT NULL DEFAULT '[]',
    status         TEXT NOT NULL DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_ca_hits_last_seen ON ca_hits(last_seen DESC);
"""

# Columns that came after the first schema. `CREATE TABLE IF NOT EXISTS` does not
# add them to an existing file, `_migrate` does.
ADDED_COLUMNS = {
    "findings": {
        "enrich_attempts": "INTEGER NOT NULL DEFAULT 0",
        "domain_changed": "TEXT",
        "escalated_at": "TEXT",
        # Records that somebody explicitly asked for this finding to be enriched.
        # Without this column `enrich_state='pending'` was the only marker, and rows
        # from the time when enrichment still ran automatically carried it too.
        "enrich_requested_at": "TEXT",
        # The registrar's abuse contact for the abuse report (§17.2):
        # an organisational address, see the allowlist in enrich/rdap.py.
        "registrar_abuse_email": "TEXT",
        # JSON: {service: {scan_id, result, visibility, ...}}, the analyses that were
        # triggered. One column instead of two per service, because services get added.
        "scans": "TEXT",
        # What the score would be WITH registration data. Deliberately its own column:
        # a finding's score must not change behind somebody's back while they are
        # looking at it.
        "score_enriched": "INTEGER",
        "enrich_note": "TEXT",
    },
}

# The two German CA tables, as they were called before the translation.
LEGACY_TABLES = (
    ("ca_sperrliste", "ca_revocations", {
        "quelle": "source", "art": "kind", "wert": "value", "grund": "reason",
        "verweis": "reference", "aktiv": "active", "angelegt": "created_at",
    }),
    ("ca_funde", "ca_hits", {
        "zuerst": "first_seen", "zuletzt": "last_seen", "treffer": "hit_count",
        "gesperrt": "revoked_issuer", "glied_sha256": "link_sha256",
        "glied_subjekt": "link_subject", "grund": "reason", "verweis": "reference",
        "namen": "names", "namen_gesamt": "names_total", "kette": "chain",
    }),
)
LEGACY_INDEXES = {"ca_sperrliste": "idx_sperrliste_quelle", "ca_funde": "idx_ca_funde_zuletzt"}


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    """A connection with WAL; creates the schema if missing (`CREATE ... IF NOT EXISTS`)."""
    conn = sqlite3.connect(str(path or settings.database_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    # Several processes share this file: the application, the backup, the CA watch,
    # now and then a script. WAL allows that, but without a wait the second writer
    # gets "database is locked" right away instead of waiting a moment. Five seconds
    # is more than a write in here ever needs.
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    _rename_legacy(conn)
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.commit()
    return conn


def _rename_legacy(conn: sqlite3.Connection) -> None:
    """Rename the two German CA tables in place. Runs before the schema is created.

    An installation that has been running keeps its rows. Order matters: once
    `CREATE TABLE IF NOT EXISTS` has made the new empty table, renaming the old
    one fails because the target already exists.
    """
    tables = {r["name"] for r in
              conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for old, fresh, cols in LEGACY_TABLES:
        if old not in tables or fresh in tables:
            continue
        conn.execute(f"ALTER TABLE {old} RENAME TO {fresh}")
        for was, now in cols.items():
            conn.execute(f'ALTER TABLE {fresh} RENAME COLUMN "{was}" TO "{now}"')
        conn.execute(f"DROP INDEX IF EXISTS {LEGACY_INDEXES[old]}")
        if fresh == "ca_hits":
            for was, now in (("neu", "new"), ("geprueft", "checked"), ("harmlos", "benign")):
                conn.execute("UPDATE ca_hits SET status=? WHERE status=?", (now, was))
        else:
            conn.execute("UPDATE ca_revocations SET source='manual' WHERE source='manuell'")
            conn.execute("UPDATE ca_revocations SET kind='issuer_serial'"
                         " WHERE kind='aussteller_serie'")
    conn.commit()


def _migrate(conn: sqlite3.Connection) -> None:
    # Deliberately simple: additive columns only. A real migration tool once a column
    # has to be renamed or removed.
    for table, cols in ADDED_COLUMNS.items():
        have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in cols.items():
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    # Leftovers from the time of automatic enrichment: `pending` without a request.
    # They would be picked up on the next start and would fire off queries nobody
    # asked for. Switch them off once. They can be requested again at any time.
    conn.execute(
        "UPDATE findings SET enrich_state='skipped'"
        " WHERE enrich_state='pending' AND enrich_requested_at IS NULL"
    )


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value else None


def upsert_finding(
    conn: sqlite3.Connection,
    tenant_id: str,
    cand: CandidateName,
    cert: CertContext,
    *,
    score: int,
    severity: str,
    explanation: dict | list,
    score_phase1: int | None = None,
    related_names: list[str] | None = None,
    enrich_state: str = "pending",
    now: datetime | None = None,
) -> tuple[str, str]:
    """Finding dedupe (§4.4). Returns `(finding_id, "insert"|"update"|"rescore")`.

    A hit on `(tenant_id, registrable)` within `dedupe_finding_ttl`: only bump
    `last_seen`/`cert_count`, no new record, no enrichment, no alert. Exception:
    the score rises by more than `rescore_delta`.
    """
    now = now or datetime.now(UTC)
    cutoff = _iso(now - timedelta(seconds=settings.dedupe_finding_ttl))
    row = conn.execute(
        "SELECT id, score FROM findings WHERE tenant_id=? AND registrable=? AND last_seen>=?"
        " ORDER BY last_seen DESC LIMIT 1",
        (tenant_id, cand.registrable, cutoff),
    ).fetchone()

    if row is not None:
        if score - row["score"] > settings.rescore_delta:
            conn.execute(
                # The new value is a phase 1 score; phase 2 adds the enrichment on top.
                "UPDATE findings SET last_seen=?, cert_count=cert_count+1, hit_count=hit_count+1,"
                " score=?, score_phase1=?, severity=?, explanation=? WHERE id=?",
                (_iso(now), score, score_phase1 if score_phase1 is not None else score,
                 severity, json.dumps(explanation), row["id"]),
            )
            action = "rescore"
        else:
            conn.execute(
                "UPDATE findings SET last_seen=?, cert_count=cert_count+1, hit_count=hit_count+1"
                " WHERE id=?",
                (_iso(now), row["id"]),
            )
            action = "update"
        conn.commit()
        return row["id"], action

    finding_id = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO findings (
            id, tenant_id, domain, registrable, tld, is_idn, is_wildcard, unicode_form,
            score, score_phase1, severity, severity_at_creation, explanation,
            first_seen, last_seen, cert_sha256, cert_not_before, cert_not_after,
            issuer_o, san_count, related_names, ct_log_id, ct_log_index, enrich_state
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            finding_id, tenant_id, cand.name, cand.registrable, cand.tld,
            int(cand.is_idn), int(cand.wildcard), cand.unicode if cand.is_idn else None,
            score, score_phase1 if score_phase1 is not None else score,
            severity, severity, json.dumps(explanation),
            _iso(now), _iso(now), cert.sha256, _iso(cert.not_before), _iso(cert.not_after),
            cert.issuer_o, len(cert.names), json.dumps((related_names or [])[:20]),
            cert.log_id, cert.idx, enrich_state,
        ),
    )
    conn.commit()
    return finding_id, "insert"


def audit_log(
    conn: sqlite3.Connection, action: str, target: str, detail: str = "", source: str = ""
) -> None:
    """Record an irreversible action.

    Survives container rebuilds, because the database sits on its own volume.
    Without a user id on purpose. The application has no login (§1.2); what gets
    recorded is what the operating system sees anyway.
    """
    conn.execute(
        "INSERT INTO audit (at, action, target, detail, source) VALUES (?,?,?,?,?)",
        (datetime.now(UTC).isoformat(), action, target, detail or None, source or None),
    )
    conn.commit()


def sync_tenants(conn: sqlite3.Connection, rulesets: list) -> None:
    """`findings.tenant_id` has a foreign key. The row has to exist."""
    for rs in rulesets:
        conn.execute(
            "INSERT INTO tenants (id, name, enabled, tlp, ruleset_hash, ruleset_loaded)"
            " VALUES (?,?,?,?,?,?)"
            " ON CONFLICT(id) DO UPDATE SET name=excluded.name, enabled=excluded.enabled,"
            " tlp=excluded.tlp, ruleset_hash=excluded.ruleset_hash,"
            " ruleset_loaded=excluded.ruleset_loaded",
            (
                rs.tenant.id,
                rs.tenant.name,
                int(rs.tenant.enabled),
                rs.tenant.tlp,
                rs.ruleset_hash,
                datetime.now(UTC).isoformat(),
            ),
        )
    conn.commit()


def purge_old_findings(conn: sqlite3.Connection, days: int | None = None) -> int:
    """Retention (§9.3). Confirmed and reported findings stay indefinitely.

    The specification has a separate archive table for this; that belongs to the
    partitioned PostgreSQL, where a partition drops as a whole. Here the exclusion
    in the DELETE is enough. Same result with one table less.
    """
    age = days if days is not None else settings.retention_days
    cutoff = _iso(datetime.now(UTC) - timedelta(days=age))
    cur = conn.execute(
        "DELETE FROM findings WHERE first_seen < ? AND status NOT IN ('confirmed','reported')",
        (cutoff,),
    )
    conn.commit()
    return cur.rowcount


# --------------------------- Enrichment cache ---------------------------


def cache_get(conn: sqlite3.Connection, source: str, key: str, now: datetime | None = None):
    """A cached result or `None`. Expired counts as not there."""
    row = conn.execute(
        "SELECT data FROM enrich_cache WHERE source=? AND key=? AND expires_at>?",
        (source, key, _iso(now or datetime.now(UTC))),
    ).fetchone()
    return json.loads(row["data"]) if row else None


def cache_put(
    conn: sqlite3.Connection, source: str, key: str, data, ttl: float, now: datetime | None = None
) -> None:
    expires = _iso((now or datetime.now(UTC)) + timedelta(seconds=ttl))
    conn.execute(
        "INSERT OR REPLACE INTO enrich_cache (source, key, data, expires_at) VALUES (?,?,?,?)",
        (source, key, json.dumps(data), expires),
    )
    conn.commit()


def cache_purge(conn: sqlite3.Connection, now: datetime | None = None) -> int:
    """Nothing stays past its TTL (§16.2), not even filtered."""
    cur = conn.execute("DELETE FROM enrich_cache WHERE expires_at<=?", (_iso(now or datetime.now(UTC)),))
    conn.commit()
    return cur.rowcount


# --------------------------- Daily quotas -------------------------------


def quota_take(conn: sqlite3.Connection, day: str, limits: dict[str, int]) -> str | None:
    """Bumps every key by one, or returns the first exhausted key and counts nothing
    at all. All in one transaction."""
    counts = quota_counts(conn, day)
    for key, limit in limits.items():
        if counts.get(key, 0) >= limit:
            return key
    conn.executemany(
        "INSERT INTO enrich_quota (day, key, n) VALUES (?,?,1)"
        " ON CONFLICT(day, key) DO UPDATE SET n=n+1",
        [(day, key) for key in limits],
    )
    conn.commit()
    return None


def quota_counts(conn: sqlite3.Connection, day: str) -> dict[str, int]:
    return {r["key"]: r["n"] for r in conn.execute("SELECT key, n FROM enrich_quota WHERE day=?", (day,))}
