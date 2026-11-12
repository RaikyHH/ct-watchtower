from datetime import UTC, datetime, timedelta

import pytest

from ctwatchtower import db
from ctwatchtower.config import settings
from ctwatchtower.normalize.names import CertContext, normalize


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "test.sqlite3")
    c.execute("INSERT INTO tenants (id, name) VALUES ('acme', 'ACME')")
    c.commit()
    yield c
    c.close()


def cert(names=("payli0-secure.top",)) -> CertContext:
    now = datetime.now(UTC)
    return CertContext(
        log_id="oak2026h1",
        idx=918273645,
        seen_at=now,
        not_before=now,
        not_after=now + timedelta(days=90),
        issuer_cn="E7",
        issuer_o="Let's Encrypt",
        serial="03a1",
        sha256="9f2c",
        is_precert=True,
        names=list(names),
    )


def add(conn, score=70, name="payli0-secure.top", **kw):
    return db.upsert_finding(
        conn, "acme", normalize(name), cert(),
        score=score, severity="warning", explanation={"contributions": []}, **kw
    )


def test_wal_is_active(conn):
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_schema_is_created_and_idempotent(tmp_path):
    path = tmp_path / "twice.sqlite3"
    db.connect(path).close()
    conn = db.connect(path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"tenants", "findings", "campaigns", "daily_stats"} <= tables


def test_insert_stores_cert_context_without_raw_certificate(conn):
    fid, action = add(conn)
    assert action == "insert"
    row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["registrable"] == "payli0-secure.top"
    assert row["ct_log_id"] == "oak2026h1" and row["ct_log_index"] == 918273645
    assert row["san_count"] == 1 and row["severity_at_creation"] == "warning"
    assert row["cert_count"] == 1 and row["status"] == "new"


def test_duplicate_within_ttl_only_bumps_counters(conn):
    fid, _ = add(conn, score=70)
    same_id, action = add(conn, score=75)
    assert (same_id, action) == (fid, "update")
    row = conn.execute("SELECT * FROM findings").fetchone()
    assert conn.execute("SELECT count(*) FROM findings").fetchone()[0] == 1
    assert row["cert_count"] == 2 and row["hit_count"] == 2 and row["score"] == 70


def test_score_jump_beyond_rescore_delta_updates_and_reports(conn):
    fid, _ = add(conn, score=40)
    same_id, action = add(conn, score=40 + settings.rescore_delta + 1)
    assert (same_id, action) == (fid, "rescore")
    row = conn.execute("SELECT * FROM findings").fetchone()
    assert row["score"] == 56 and row["severity_at_creation"] == "warning"


def test_expired_dedupe_window_creates_a_new_finding(conn):
    old = datetime.now(UTC) - timedelta(seconds=settings.dedupe_finding_ttl + 60)
    add(conn, now=old)
    _, action = add(conn)
    assert action == "insert"
    assert conn.execute("SELECT count(*) FROM findings").fetchone()[0] == 2


def test_retention_keeps_confirmed_findings(conn):
    old = datetime.now(UTC) - timedelta(days=200)
    keep, _ = add(conn, now=old)
    conn.execute("UPDATE findings SET status='confirmed' WHERE id=?", (keep,))
    conn.commit()
    add(conn, name="vantabank-login.top", now=old)
    assert db.purge_old_findings(conn, days=90) == 1
    assert [r[0] for r in conn.execute("SELECT id FROM findings")] == [keep]
