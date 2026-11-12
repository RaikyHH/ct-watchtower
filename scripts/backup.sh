#!/bin/sh
# Back up both volumes: `db` (findings, tenants, audit trail) and `rules` (rulesets,
# the productive ones included). Run it before every `docker compose build` - a
# deleted volume is gone for good.
#
#   sh scripts/backup.sh [target directory]      # default: ./backups
#
# The database is copied with `Connection.backup()`, not with `tar`: a running
# application keeps writing into the WAL, and a blindly copied file would be caught
# mid-write.
set -eu

TARGET="${1:-backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$TARGET"
cd "$(dirname "$0")/.."

# Address the volumes through the container, not by their name: that carries the
# project name as a prefix and differs depending on the folder.
CONTAINER="$(docker compose ps -aq app)"
[ -n "$CONTAINER" ] || { echo "no app container, run 'docker compose up -d' first" >&2; exit 1; }

if docker compose ps --status running app | grep -q app; then
  docker compose exec -T app python -c "import sqlite3; q=sqlite3.connect('/data/ctwatchtower.sqlite3'); z=sqlite3.connect('/tmp/backup.sqlite3'); q.backup(z); z.close()"
  docker compose exec -T app sh -c 'cat /tmp/backup.sqlite3; rm -f /tmp/backup.sqlite3' > "$TARGET/db-$STAMP.sqlite3"
else
  # With no running container nobody is writing any more, so the file itself is
  # enough, WAL and shared memory included in case the last run did not end cleanly.
  echo "app is not running, copying the volume at rest" >&2
  docker run --rm --volumes-from "$CONTAINER" alpine sh -c 'cd /data && tar cf - .' > "$TARGET/db-$STAMP.tar"
fi

# Rulesets are text files, an archive is enough for those.
docker run --rm --volumes-from "$CONTAINER" alpine sh -c 'cd /app/rules && tar cf - .' > "$TARGET/rules-$STAMP.tar"

echo "backed up to $TARGET:"
ls -lh "$TARGET" | grep "$STAMP"
