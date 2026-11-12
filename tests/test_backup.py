"""The nightly backup: that it copies what it should and clears old copies away."""

from __future__ import annotations

import importlib
import sqlite3
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


@pytest.fixture
def backup(tmp_path, monkeypatch):
    """The script reads its paths from the environment at import time."""
    db = tmp_path / "ctw.sqlite3"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE findings (id TEXT, domain TEXT)")
    conn.execute("INSERT INTO findings VALUES ('1', 'example.com')")
    conn.commit()
    conn.close()

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "customer.yaml").write_text("tenant: {id: customer, name: Customer}\n",
                                         encoding="utf-8")

    monkeypatch.setenv("DATABASE_PATH", str(db))
    monkeypatch.setenv("RULES_PATH", str(rules))
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("BACKUP_KEEP", "14")
    monkeypatch.syspath_prepend(str(SCRIPTS))
    module = importlib.import_module("backup")
    yield importlib.reload(module)
    sys.modules.pop("backup", None)


def test_the_backup_copies_database_and_rules(backup, tmp_path):
    backup.once()
    target = tmp_path / "backups"
    db_copy = next(target.glob("db-*.sqlite3"))
    archive = next(target.glob("rules-*.tar.gz"))

    # Readable and complete. A WAL database copied through the file system might well
    # be caught mid-write at this point.
    conn = sqlite3.connect(db_copy)
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("SELECT domain FROM findings").fetchone()[0] == "example.com"
    conn.close()

    with tarfile.open(archive) as tar:
        assert "./customer.yaml" in tar.getnames()


def test_old_copies_go_and_fresh_ones_stay(backup, tmp_path):
    target = tmp_path / "backups"
    target.mkdir()
    old = target / "db-20200101T000000Z.sqlite3"
    old.write_text("old", encoding="utf-8")
    long_ago = (datetime.now(UTC) - timedelta(days=30)).timestamp()
    import os

    os.utime(old, (long_ago, long_ago))

    backup.once()
    assert not old.exists()
    assert list(target.glob("db-*.sqlite3")), "the fresh copy was cleared away with it"


def test_keep_zero_throws_nothing_away(backup, tmp_path, monkeypatch):
    """Whoever sets `BACKUP_KEEP=0` wants to keep everything, not lose everything."""
    monkeypatch.setattr(backup, "KEEP", 0)
    target = tmp_path / "backups"
    target.mkdir()
    old = target / "db-20200101T000000Z.sqlite3"
    old.write_text("old", encoding="utf-8")
    import os

    os.utime(old, (0, 0))
    assert backup.clean_up(datetime.now(UTC)) == 0
    assert old.exists()


def test_the_next_run_always_lies_in_the_future(backup):
    now = datetime(2026, 5, 1, 14, 30, tzinfo=UTC)
    nxt = backup._next_run(now)
    assert nxt > now
    assert (nxt - now) <= timedelta(days=1)
