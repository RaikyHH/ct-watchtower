"""The nightly backup inside the container: database and rulesets.

Runs as a service of its own (`docker compose up -d backup`) next to the application
and reaches the same volumes directly. No Docker socket: handing that into a
container means handing it control of the host, which is a disproportionate price for
a file copy.

The database is copied through `sqlite3.Connection.backup()`, not through the file
system. The application keeps writing into the WAL meanwhile; a blindly copied file
would be caught mid-write.

    BACKUP_AT=03:00     the time (UTC), default 03:00
    BACKUP_KEEP=14      keep this many days, default 14
    BACKUP_DIR=/backups
"""

from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import sys
import tarfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

log = logging.getLogger("backup")

DATABASE = Path(os.environ.get("DATABASE_PATH", "/data/ctwatchtower.sqlite3"))
RULES = Path(os.environ.get("RULES_PATH", "/app/rules"))
TARGET = Path(os.environ.get("BACKUP_DIR", "/backups"))
KEEP = int(os.environ.get("BACKUP_KEEP", "14"))
AT = os.environ.get("BACKUP_AT", "03:00")


def _next_run(now: datetime) -> datetime:
    hour, _, minute = AT.partition(":")
    target = now.replace(hour=int(hour), minute=int(minute or 0), second=0, microsecond=0)
    return target if target > now else target + timedelta(days=1)


def back_up(stamp: str) -> list[Path]:
    TARGET.mkdir(parents=True, exist_ok=True)
    made = []

    db_target = TARGET / f"db-{stamp}.sqlite3"
    source = sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)
    try:
        copy = sqlite3.connect(db_target)
        try:
            source.backup(copy)
        finally:
            copy.close()
    finally:
        source.close()
    made.append(db_target)

    rules_target = TARGET / f"rules-{stamp}.tar.gz"
    with tarfile.open(rules_target, "w:gz") as archive:
        archive.add(RULES, arcname=".")
    made.append(rules_target)
    return made


def clean_up(now: datetime) -> int:
    """Remove copies older than `KEEP` days. 0 means: throw nothing away."""
    if KEEP <= 0:
        return 0
    limit = (now - timedelta(days=KEEP)).timestamp()
    removed = 0
    for path in TARGET.glob("*-*"):
        if path.is_file() and path.stat().st_mtime < limit:
            path.unlink()
            removed += 1
    return removed


def once() -> None:
    now = datetime.now(UTC)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    files = back_up(stamp)
    free = shutil.disk_usage(TARGET).free // (1024 * 1024)
    log.info(
        "backed up: %s (%s) · %d old copies removed · %d MB free",
        ", ".join(f.name for f in files),
        ", ".join(f"{f.stat().st_size // 1024} KB" for f in files),
        clean_up(now),
        free,
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if "--once" in sys.argv:
        once()
        return 0
    log.info("the backup runs daily at %s UTC, %d days are kept", AT, KEEP)
    while True:
        sleep_for = (_next_run(datetime.now(UTC)) - datetime.now(UTC)).total_seconds()
        time.sleep(max(1.0, sleep_for))
        try:
            once()
        except Exception:  # noqa: BLE001 - one failure must not end the service
            log.exception("backup failed, next attempt tomorrow")


if __name__ == "__main__":
    raise SystemExit(main())
