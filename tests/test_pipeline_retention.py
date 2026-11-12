"""The pipeline's retention job (§9.3): deletes old `new` findings, leaves confirmed ones."""

from datetime import UTC, datetime, timedelta

from ctwatchtower import db
from ctwatchtower.normalize.names import CertContext, normalize
from ctwatchtower.pipeline import Pipeline


class _NoRules:
    rulesets: list = []


def _cert() -> CertContext:
    now = datetime.now(UTC)
    return CertContext("log", 1, now, None, None, "", "", "", "ab", False, ["x.top"])


def test_retention_deletes_old_new_findings_and_keeps_confirmed(tmp_path):
    conn = db.connect(tmp_path / "r.sqlite3")
    conn.execute("INSERT INTO tenants (id, name) VALUES ('acme', 'ACME')")
    old = datetime.now(UTC) - timedelta(days=200)
    ids = {}
    for name, status in (("a-old.top", "new"), ("b-old.top", "confirmed"), ("c-old.top", "reported")):
        fid, _ = db.upsert_finding(
            conn, "acme", normalize(name), _cert(),
            score=70, severity="warning", explanation={}, now=old,
        )
        conn.execute("UPDATE findings SET status=? WHERE id=?", (status, fid))
        ids[status] = fid
    fresh, _ = db.upsert_finding(
        conn, "acme", normalize("d-fresh.top"), _cert(), score=70, severity="warning", explanation={}
    )
    conn.commit()

    pipe = Pipeline(conn, _NoRules(), url="ws://127.0.0.1:1")
    assert pipe.run_retention() == 1
    left = {r[0] for r in conn.execute("SELECT id FROM findings")}
    assert left == {ids["confirmed"], ids["reported"], fresh}


def test_retention_thread_stops_with_pipeline(tmp_path):
    pipe = Pipeline(db.connect(tmp_path / "s.sqlite3"), _NoRules(), url="ws://127.0.0.1:1")
    pipe.start()
    retention = next(t for t in pipe._threads if t.name == "retention")
    assert retention.is_alive()
    pipe.stop()
    assert not retention.is_alive()
